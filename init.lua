-- Tested with wireshark 2.8

u2f_proto = Proto("u2f", "U2F")

local cids = {[0xffffffff] = "BROADCAST"}
local cmds = {
        [bit32.bor(0x80, 0x03)] = "U2FHID_MSG",
        [bit32.bor(0x80, 0x06)] = "U2FHID_INIT",
        [bit32.bor(0x80, 0x10)] = "CTAPHID_CBOR",
        [bit32.bor(0x80, 0x3b)] = "CTAPHID_KEEPALIVE",
        [bit32.bor(0x80, 0x3f)] = "U2FHID_ERROR",
        [bit32.bor(0x80, 0x40)] = "U2FHID_VENDOR0",
        [bit32.bor(0x80, 0x41)] = "U2FHID_VENDOR1",
}
local f_cid = ProtoField.uint32("u2f.cid", "CID", base.HEX, cids)
local f_cmd = ProtoField.uint8("u2f.cmd", "CMD", base.HEX, cmds)
local f_seq = ProtoField.uint8("u2f.seq", "SEQ", base.DEC)
local f_bcnt = ProtoField.uint16("u2f.bcnt", "BCNT", base.DEC)
local f_payload = ProtoField.bytes("u2f.data", "Data", base.NONE)

local f_init_nonce = ProtoField.bytes("u2f.init.nonce", "NONCE", base.NONE)
local f_init_cid = ProtoField.uint32("u2f.init.cid", "CID", base.HEX)
local f_init_version = ProtoField.uint8("u2f.init.version", "VERSION", base.DEC)
local f_init_cap = ProtoField.uint8("u2f.init.capabilities", "CAP", base.HEX)

local u2f_inss = {
        [1] = "U2F_REGISTER",
        [2] = "U2F_AUTHENTICATE",
        [3] = "U2F_VERSION",
        [0x40] = "U2F_VENDOR0",
        [0x41] = "U2F_VENDOR1",
}
local f_msg_ins = ProtoField.uint8("u2f.msg.ins", "INS", base.HEX, u2f_inss)
local u2f_p1s = {
        [3] = "enforce-user-presence-and-sign",
        [7] = "check-only",
        [8] = "dont-enforce-user-presence-and-sign",
}
local f_msg_p1 = ProtoField.uint8("u2f.msg.p1", "P1", base.HEX, u2f_p1s)

local bytes_left = 0

u2f_proto.fields = {
        f_cid, f_cmd, f_seq, f_bcnt, f_payload, f_init_nonce, f_init_cid, f_init_version,
        f_init_cap, f_msg_ins, f_msg_p1
}

local cbor_proto = Dissector.get("cbor")

function u2f_proto.dissector(buffer, pinfo, tree)

        pinfo.cols['protocol'] = "U2F"

        local subtree = tree:add(u2f_proto, buffer(), "U2F Data")

        -- local cid = buffer(0,4):uint()
        local cmd = buffer(4, 1):uint()

        subtree:add(f_cid, buffer(0, 4))

        if bit32.btest(cmd, 0x80) then
                local bcnt = buffer(5,2):uint()
                subtree:add(f_cmd, buffer(4, 1))
                subtree:add(f_bcnt, buffer(5, 2))

                if cmd == bit32.bor(0x80, 0x01) then
                        pinfo.cols['info'] = "U2FHID ECHO"
                elseif cmd == bit32.bor(0x80, 0x03) then
                        pinfo.cols['info'] = "U2FHID MSG"
                        -- Responses do not have these fields. But we cannot track conversations
                        -- in a lua implementation of this protocol
                        local msgtree = subtree:add("MSG"), buffer(7, math.min(bcnt, 64-7))
                        msgtree:add(f_msg_ins, buffer(8,1))
                        msgtree:add(f_msg_p1, buffer(9, 1))
                elseif cmd == bit32.bor(0x80, 0x04) then
                        pinfo.cols['info'] = "U2FHID LOCK"
                elseif cmd == bit32.bor(0x80, 0x06) then
                        pinfo.cols['info'] = "U2FHID INIT"
                        local inittree = subtree:add("INIT", buffer(7, bcnt))
                        inittree:add(f_init_nonce, buffer(7,8))
                        if bcnt == 17 then
                                inittree:add(f_init_cid, buffer(15, 4))
                                inittree:add(f_init_version, buffer(19, 1))
                                inittree:add(f_init_cap, buffer(23, 1))
                        end
                elseif cmd == bit32.bor(0x80, 0x08) then
                        pinfo.cols['info'] = "U2FHID WINK"
                -- TODO: Create a separate wslua script for CTAP
                elseif cmd == bit32.bor(0x80, 0x10) then
                        pinfo.cols['info'] = "CTAPHID CBOR"
                elseif cmd == bit32.bor(0x80, 0x3b) then
                        pinfo.cols['info'] = "CTAPHID KEEPALIVE"
                elseif cmd == bit32.bor(0x80, 0x3c) then
                        pinfo.cols['info'] = "U2FHID SYNC"
                elseif cmd == bit32.bor(0x80, 0x3f) then
                        pinfo.cols['info'] = "U2FHID ERROR"
                elseif cmd >= bit32.bor(0x80, 0x40) and cmd < bit32.bor(0x80, 0x7f) then
                        pinfo.cols['info'] = "U2FHID VENDOR" .. cmd - 0x80 - 0x40
                end
                if bcnt > 64-7 then
                        -- pinfo.desegment_len = bcnt - (64-7)
                        bytes_left = bcnt - (64-7)
                        subtree:add(f_payload, buffer(7, 64-7))
                        -- Need to figure out how to merge packets first...
                        -- cbor_proto:call(buffer(7, 64-7):tvb(), pinfo, tree)
                else
                        subtree:add(f_payload, buffer(7, bcnt))
                end
        else
                subtree:add(f_seq, buffer(4,1))
                pinfo.cols['info'] = "U2FHID Continuation"
                if bytes_left > 64-5 then
                        subtree:add(f_payload, buffer(5,64-5))
                        bytes_left = bytes_left - (64-5)
                else
                        subtree:add(f_payload, buffer(5,bytes_left))
                        bytes_left = 0
                end
        end
end



usbhid_table = DissectorTable.get("usb.interrupt", USBHID)

usbhid_table:add(0xffff, u2f_proto)


