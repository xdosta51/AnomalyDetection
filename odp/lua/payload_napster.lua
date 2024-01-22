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
detection_name: Napster
version: 1
description: Audio streaming and MP3 store.
bundle_description: $VAR1 = {
          'Napster' => 'Audio streaming and MP3 store.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "Napster",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        validate =  'DetectorValidator',
        minimum_matches =  1
    }
}

function DetectorClean()
end

function DetectorInit(detectorInstance)
    gDetector = detectorInstance
    gDetector:addHttpPattern(2, 5, 0, 0, 0, 54, 13, 'Napster', 319, 1);
    gDetector:addHttpPattern(1, 0, 0, 0, 0, 54, 13, 'napster', 319, 1);
    return gDetector
end

function DetectorValidator()
    local context = {}
    return serviceFail(context)
end

function DetectorFini()
end
