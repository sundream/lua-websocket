-- Copyright (C) Yichun Zhang (agentzh)


-- FIXME: this library is very rough and is currently just for testing
--        the websocket server.


local wbproto = require "websocket.protocol"
local socket = require "skynet.socket"
local crypt = require "skynet.crypt"


local _recv_frame = wbproto.recv_frame
local _send_frame = wbproto.send_frame
local new_tab = wbproto.new_tab
local tcp = socket.tcp
local encode_base64 = crypt.base64encode
local concat = table.concat
local char = string.char
local str_find = string.find
local rand = math.random
local setmetatable = setmetatable
local type = type
local ssl_support = false

local function rshift(number,bits)
    return number >> bits
end

local function band(num1,num2)
    return num1 & num2
end

local function socket_connect(host,port)
    return socket.open(host,port)
end

local function socket_close(sock)
    socket.close(sock)
    return true
end

local function socket_write(sock,data)
    socket.write(sock,data)
    return true
end

local function socket_read_until(sock,sep)
    return socket.readline(sock,sep)
end

local _M = new_tab(0, 13)
_M._VERSION = '0.07'

local mt = { __index = _M }


function _M.new(self, opts)
    local max_payload_len, send_masked, force_masking
    if opts then
        max_payload_len = opts.max_payload_len
        send_masked = opts.send_masked
        force_masking = opts.force_masking
    end

    return setmetatable({
        max_payload_len = max_payload_len or 65535,
        send_masked = send_masked,
        force_masking = force_masking,
    }, mt)
end


function _M.connect(self, uri, opts)
    local scheme,host,path = string.match(uri,[[^(wss?)://([^/]+)(.*)]])
    if not (scheme and host and path) then
        return nil, "bad websocket uri"
    end
    local port = 80

    local has_port = string.find(host,":")
    if has_port then
        host,port = string.match(host,"^(.+):(%d+)")
        port = tonumber(port)
        if not (host and port) then
            return nil, "bad websocket uri"
        end
    end

    if path == "" then
        path = "/"
    end

    local ssl_verify, proto_header, origin_header = false

    if opts then
        local protos = opts.protocols
        if protos then
            if type(protos) == "table" then
                proto_header = "\r\nSec-WebSocket-Protocol: "
                               .. concat(protos, ",")

            else
                proto_header = "\r\nSec-WebSocket-Protocol: " .. protos
            end
        end

        local origin = opts.origin
        if origin then
            origin_header = "\r\nOrigin: " .. origin
        end

        if opts.ssl_verify then
            if not ssl_support then
                return nil,"not support ssl"
            end
            ssl_verify = true
        end
    end

    local sock,err = socket_connect(host, port)
    if not sock then
        return nil,err
    end
    self.sock = sock

    if scheme == "wss" then
        if not ssl_support then
            return nil,"not support ssl"
        end
    end

    -- do the websocket handshake:

    local bytes = char(rand(256) - 1, rand(256) - 1, rand(256) - 1,
                       rand(256) - 1, rand(256) - 1, rand(256) - 1,
                       rand(256) - 1, rand(256) - 1, rand(256) - 1,
                       rand(256) - 1, rand(256) - 1, rand(256) - 1,
                       rand(256) - 1, rand(256) - 1, rand(256) - 1,
                       rand(256) - 1)

    local key = encode_base64(bytes)
    local req = "GET " .. path .. " HTTP/1.1\r\nUpgrade: websocket\r\nHost: "
                .. host .. ":" .. port
                .. "\r\nSec-WebSocket-Key: " .. key
                .. (proto_header or "")
                .. "\r\nSec-WebSocket-Version: 13"
                .. (origin_header or "")
                .. "\r\nConnection: Upgrade\r\n\r\n"

    local bytes, err = socket_write(self.sock,req)
    if not bytes then
        return nil, "failed to send the handshake request: " .. err
    end

    -- read until CR/LF
    local header = socket_read_until(self.sock,"\r\n\r\n")
    if not header then
        return nil, "failed to receive response header: " .. err
    end

    -- FIXME: verify the response headers
    
    local m = string.match(header, [[^%s*HTTP/1%.1%s+]])
    if not m then
        return nil, "bad HTTP response status line: " .. header
    end

    return 1
end

function _M.recv_frame(self)
    if self.fatal then
        return nil, nil, "fatal error already happened"
    end

    local sock = self.sock
    if not sock then
        return nil, nil, "not initialized yet"
    end

    local data, typ, err =  _recv_frame(sock, self.max_payload_len, self.force_masking)
    if not data and not str_find(err, ": timeout", 1, true) then
        self.fatal = true
    end
    return data, typ, err
end


local function send_frame(self, fin, opcode, payload)
    if self.fatal then
        return nil, "fatal error already happened"
    end

    if self.closed then
        return nil, "already closed"
    end

    local sock = self.sock
    if not sock then
        return nil, "not initialized yet"
    end

    local bytes, err = _send_frame(sock, fin, opcode, payload,
                                   self.max_payload_len,self.send_masked)
    if not bytes then
        self.fatal = true
    end
    return bytes, err
end
_M.send_frame = send_frame


function _M.send_text(self, data)
    return send_frame(self, true, 0x1, data)
end


function _M.send_binary(self, data)
    return send_frame(self, true, 0x2, data)
end


local function send_close(self, code, msg)
    local payload
    if code then
        if type(code) ~= "number" or code > 0x7fff then
            return nil, "bad status code"
        end
        payload = char(band(rshift(code, 8), 0xff), band(code, 0xff))
                        .. (msg or "")
    end

    local bytes, err = send_frame(self, true, 0x8, payload)

    if not bytes then
        self.fatal = true
    end

    self.closed = true

    return bytes, err
end
_M.send_close = send_close


function _M.send_ping(self, data)
    return send_frame(self, true, 0x9, data)
end


function _M.send_pong(self, data)
    return send_frame(self, true, 0xa, data)
end


function _M.close(self,code,msg)
    if self.fatal then
        return nil, "fatal error already happened"
    end

    local sock = self.sock
    if not sock then
        return nil, "not initialized"
    end

    if not self.closed then
        local bytes, err = send_close(self,code,msg)
        if not bytes then
            return nil, "failed to send close frame: " .. err
        end
    end

    return socket_close(sock)
end

return _M
