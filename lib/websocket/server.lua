-- Copyright (C) Yichun Zhang (agentzh)

local socket = require "skynet.socket"
local crypt = require "skynet.crypt"
local wbproto = require "websocket.protocol"

local new_tab = wbproto.new_tab
local _recv_frame = wbproto.recv_frame
local _send_frame = wbproto.send_frame
local str_lower = string.lower
local char = string.char
local str_find = string.find
local sha1 = crypt.sha1
local base64encode = crypt.base64encode
local type = type
local setmetatable = setmetatable
local tostring = tostring
-- local print = print


local function rshift(number,bits)
    return number >> bits
end

local function band(num1,num2)
    return num1 & num2
end

local function socket_write(sock,data)
    socket.write(sock,data)
    return true
end

local function socket_close(sock)
    socket.close(sock)
    return true
end

local function do_handshake(sock,key,protocol)
    local accept = base64encode(sha1(key .. "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
    local handshake = string.format("HTTP/1.1 101 Switching Protocols\r\n" ..
                        "Upgrade: websocket\r\n" ..
                        "Connection: Upgrade\r\n" ..
                        "Sec-WebSocket-Accept: %s\r\n",accept)
    if protocol then
        handshake = handshake .. string.format("Sec-WebSocket-Protocol: %s\r\n", protocol)
    end
    handshake = handshake .. "\r\n"
    socket_write(sock,handshake)
end


local _M = new_tab(0, 10)
_M._VERSION = '0.07'

local mt = { __index = _M }

function _M.new(self, opts)
    local sock = assert(opts.sock)
    local headers = assert(opts.headers)

    local val = headers.upgrade
    if type(val) == "table" then
        val = val[1]
    end
    if not val or str_lower(val) ~= "websocket" then
        return nil, "bad \"upgrade\" request header: " .. tostring(val)
    end

    val = headers.connection
    if type(val) == "table" then
        val = val[1]
    end
    if not val or not str_find(str_lower(val), "upgrade", 1, true) then
        return nil, "bad \"connection\" request header"
    end

    local key = headers["sec-websocket-key"]
    if type(key) == "table" then
        key = key[1]
    end
    if not key then
        return nil, "bad \"sec-websocket-key\" request header"
    end

    local ver = headers["sec-websocket-version"]
    if type(ver) == "table" then
        ver = ver[1]
    end
    if not ver or ver ~= "13" then
        return nil, "bad \"sec-websocket-version\" request header"
    end

    local protocols = headers["sec-websocket-protocol"]
    if type(protocols) == "table" then
        protocols = protocols[1]
    end
    do_handshake(sock,key,protocols)

    local max_payload_len, send_masked, timeout,force_masking
    if opts then
        max_payload_len = opts.max_payload_len
        send_masked = opts.send_masked
        force_masking = opts.force_masking
    end

    return setmetatable({
        sock = sock,
        max_payload_len = max_payload_len or 65535,
        send_masked = send_masked,
        force_masking = force_masking,
    }, mt)
end

function _M.recv_frame(self)
    if self.fatal then
        return nil, nil, "fatal error already happened"
    end

    if self.closed then
        return nil, "already closed"
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
                                   self.max_payload_len, self.send_masked)
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


function _M.send_close(self, code, msg)
    local payload
    if code then
        if type(code) ~= "number" or code > 0x7fff then
        end
        payload = char(band(rshift(code, 8), 0xff), band(code, 0xff))
                        .. (msg or "")
    end
    return send_frame(self, true, 0x8, payload)
end


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
        local bytes, err = self:send_close(code,msg)
        self.closed = true
        if not bytes then
            return nil, "failed to send close frame: " .. err
        end
    end
    return socket_close(sock)
end


function _M.start(self,handler)
    handler.on_open(self)
    local last_recv = nil
    while true do
        local data,typ,err = self:recv_frame()
        if not data then
            self:close()
            handler.on_close(self,1000,err or "")
            break
        end
        local message
        if typ == "ping" then
            handler.on_ping(self,data)
        elseif typ == "pong" then
            handler.on_pong(self,data)
        elseif typ == "close" then
            local code,msg = err,data
            self:close()
            handler.on_close(self,code,msg)
            break
        elseif typ == "text" then
            last_recv = last_recv and last_recv .. data or data
            -- fin
            if err ~= "again" then
                message = last_recv
                last_recv = nil
            end
        elseif typ == "binary" then
            last_recv = last_recv and last_recv .. data or data
            -- fin
            if err ~= "again" then
                message = self.last_recv
                last_recv = nil
            end
        end
        if message then
            handler.on_message(self,message)
        end
    end
end

return _M
