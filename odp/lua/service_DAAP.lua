--[[
# Copyright 2001-2014 Cisco Systems, Inc. and/or its affiliates. All rights
# reserved.
#
# This file contains proprietary Detector Content created by Cisco Systems,
# Inc. or its affiliates ("Cisco") and is distributed under the GNU General
# Public License, v2 (the "GPL").  This file may also include Detector Content
# contributed by third parties. Third party contributors are identified in the
# "authors" file.  The Detector Content created by Cisco is owned by, and
# remains the property of, Cisco.  Detector Content from third party
# contributors is owned by, and remains the property of, such third parties and
# is distributed under the GPL.  The term "Detector Content" means specifically
# formulated patterns and logic to identify applications based on network
# traffic characteristics, comprised of instructions in source code or object
# code form (including the structure, sequence, organization, and syntax
# thereof), and all documentation related thereto that have been officially
# approved by Cisco.  Modifications are considered part of the Detector
# Content.
--]]
--[[
detection_name: DAAP
version: 4
description: Apple iTunes protocol.
bundle_description: $VAR1 = {
          'DAAP' => 'Apple iTunes protocol.'
        };

--]]

require "DetectorCommon"



local DC = DetectorCommon
local FT = flowTrackerModule

gServiceId = 20073
gServiceName = 'DAAP'
gDetector = nil

DetectorPackageInfo = {
    name =  "DAAP",
    proto =  DC.ipproto.tcp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
    }
}

gSfAppIdDaap = 599
gPatterns = {
     daap_resp = { "DAAP-Server: iTunes", 54, gSfAppIdDaap},
}

gFastPatterns = {
    {DC.ipproto.tcp, gPatterns.daap_resp},
}

gPorts = {
    {DC.ipproto.tcp, 3689},
}


gAppRegistry = {
	--AppIdValue          Extracts Info
	---------------------------------------
	{gSfAppIdDaap,		         1}
}

function serviceInProcess(context)

    local flowFlag = context.detectorFlow:getFlowFlag(DC.flowFlags.serviceDetected)

    if ((not flowFlag) or (flowFlag == 0)) then
        gDetector:inProcessService()
    end

    DC.printf('%s: Inprocess, packetCount: %d\n', gServiceName, context.packetCount);
    return DC.serviceStatus.inProcess
end

function serviceSuccess(context)
    local flowFlag = context.detectorFlow:getFlowFlag(DC.flowFlags.serviceDetected)

    if ((not flowFlag) or (flowFlag == 0)) then
        gDetector:addService(gServiceId, "Apple", version, gSfAppIdDaap)
    end

    DC.printf('%s: Detected, packetCount: %d\n', gServiceName, context.packetCount);
    return DC.serviceStatus.success
end

function serviceFail(context)
    local flowFlag = context.detectorFlow:getFlowFlag(DC.flowFlags.serviceDetected)

    if ((not flowFlag) or (flowFlag == 0)) then
        gDetector:failService()
    end

    context.detectorFlow:clearFlowFlag(DC.flowFlags.continue)
    DC.printf('%s: Failed, packetCount: %d\n', gServiceName, context.packetCount);
    return DC.serviceStatus.nomatch
end

function registerPortsPatterns()

    --register port based detection
    for i,v in ipairs(gPorts) do
        gDetector:addPort(v[1], v[2])
    end

    --register pattern based detection
    for i,v in ipairs(gFastPatterns) do
        if ( gDetector:registerPattern(v[1], v[2][1], #v[2][1], v[2][2], v[2][3]) ~= 0) then
            DC.printf ('%s: register pattern failed for %s\n', gServiceName,v[2][1])
        else
            DC.printf ('%s: register pattern successful for %s\n', gServiceName,v[2][1])
        end
    end

	for i,v in ipairs(gAppRegistry) do
		pcall(function () gDetector:registerAppId(v[1],v[2]) end)
	end

end

--[[ Core engine calls DetectorInit() to initialize a detector.
--]]
function DetectorInit( detectorInstance)

    gDetector = detectorInstance
    DC.printf ('%s:DetectorInit()\n', gServiceName);
    gDetector:init(gServiceName, 'DetectorValidator', 'DetectorFini')
    registerPortsPatterns()

    return gDetector
end


--[[Validator function registered in DetectorInit()
--]]
function DetectorValidator()
    local context = {}
    context.detectorFlow = gDetector:getFlow()
    context.packetDataLen = gDetector:getPacketSize()
    context.packetDir = gDetector:getPacketDir()
    context.srcIp = gDetector:getPktSrcAddr()
    context.dstIp = gDetector:getPktDstAddr()
    context.srcPort = gDetector:getPktSrcPort()
    context.dstPort = gDetector:getPktDstPort()
    context.flowKey = context.detectorFlow:getFlowKey()
    context.packetCount = gDetector:getPktCount()
    local size = context.packetDataLen
    local dir = context.packetDir
    local srcPort = context.srcPort
    local dstPort = context.dstPort
    local flowKey = context.flowKey

    DC.printf ('%s:DetectorValidator(): packetCount %d, dir %d, size %d\n', gServiceName,
               context.packetCount, dir, size);
    if (size == 0 or dir == 0) then
        return serviceInProcess(context)
    end

    if ((dir == 1) and
        (size >= 65) and
        (gDetector:memcmp(gPatterns.daap_resp[1], #gPatterns.daap_resp[1], gPatterns.daap_resp[2]) == 0))
    then
        matched, major, minor, minorer = gDetector:getPcreGroups('iTunes/([0-9]*)\\.([0-9]*)\\.([0-9]*)')
        DC.printf ('matched %s, major %s, minor %s minorer %s\n', matched, major, minor, minorer)
        if (matched) then
            context.version = string.format("%s.%s", major, minor, minorer)
            return serviceSuccess(context)
        end
    end

    return serviceFail(context)
end

--[[Required DetectorFini function
--]]
function DetectorFini()
    --print (gServiceName .. ': DetectorFini()')
end
