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
detection_name: Google
version: 8
description: Traffic generated by the Google search engine or one of the other many Internet services provided by Google Inc.
bundle_description: $VAR1 = {
          'Google Product Search' => 'Google e-commerce site.',
          'Google' => 'Traffic generated by the Google search engine or one of the other many Internet services provided by Google Inc.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "Google Safesearch",
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
    if (gDetector.CHPMultiCreateApp and gDetector.CHPMultiAddAction) then
        local handle = gDetector:CHPMultiCreateApp(184, 4, 0);
        gDetector:CHPMultiAddAction(handle, 1, 1, "www.google.", 13, "");
        gDetector:CHPMultiAddAction(handle, 0, 3, "/search?", 0, "");
        -- replace the unsafe URI parameter
        gDetector:CHPMultiAddAction(handle, 0, 3, "/setprefs", 4, ""); -- preempt false hit
        gDetector:CHPMultiAddAction(handle, 0, 3, "safe=off", 3, "safe=strict");
        gDetector:CHPMultiAddAction(handle, 0, 3, "/search?", 4, "safe=strict&");

        -- Google shopping support
        handle = gDetector:CHPMultiCreateApp(664, 4, 0);
        gDetector:CHPMultiAddAction(handle, 1, 1, "www.google.", 13, "");
        gDetector:CHPMultiAddAction(handle, 1, 3, "tbm=shop&", 0, "");
        gDetector:CHPMultiAddAction(handle, 0, 3, "/search?", 0, "");
        -- replace the unsafe URI parameter
        gDetector:CHPMultiAddAction(handle, 0, 3, "/setprefs", 4, ""); -- preempt false hit
        gDetector:CHPMultiAddAction(handle, 0, 3, "safe=off", 3, "safe=strict");
        gDetector:CHPMultiAddAction(handle, 0, 3, "/search?", 4, "safe=strict&");
    end
    return gDetector
end

function DetectorValidator()
    local context = {}
    return serviceFail(context)
end

function DetectorFini()
end