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
detection_name: SSL Group "333"
version: 3
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Twinkl' => 'Official website for Twinkl educational resources.',
          'Amp' => 'AMP is a web component framework and a website publishing technology.',
          'Zerodha' => 'Financial services company with a focus on online stock brokerage.',
          'DepartApp' => 'Platform for measurement, collection, analysis and reporting of web data.',
          'NrData' => 'Category B ISP.',
          'Microsoft Teams' => 'Microsoft Teams is a unified communication and collaboration platform for workplace communication exchange.',
          'Ballina Beach Village' => 'Website for a vacation resort where you can book and plan your trip to them.',
          'TAFE NSW' => 'TAFE NSW is Australia\'s leading provider for education and training courses.',
          'Windscribe' => 'VPN traffic generated by Windscribe.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_333",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gSSLHostPatternList = {

    -- Amp
    { 0, 4603, 'amp.dev' },
    { 0, 4603, 'ampproject.org' },
    -- NrData
    { 0, 4607, 'nrdata.net' },
    -- Twinkl
    { 0, 4608, 'twinkl.com' },
    { 0, 4608, 'twinkl.co.uk' },
    -- Zerodha
    { 0, 4609, 'zerodha.com' },
    -- Ballina Beach Village
    { 0, 4610, 'ballinabeachvillage.com.au' },
    -- TAFE NSW
    { 0, 4611, 'tafensw.edu.au' },
    -- DepartApp
    { 0, 4613, 'departapp.com' },
    -- Microsoft Teams
    { 0, 4616, 'teams.microsoft.com' },
    { 0, 4616, 'teams.events.data.microsoft.com' },
    { 0, 4616, 'api.teams.skype.com' },
    { 0, 4616, 'teams.cdn.office.net' },
    { 0, 4616, 'compass-ssl.microsoft.com' },
    { 0, 4616, 'mstea.ms' },
    -- Windscribe
    { 0, 4541, 'windscribe.com' },
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.addSSLCertPattern then
        for i,v in ipairs(gSSLHostPatternList) do
            gDetector:addSSLCertPattern(v[1],v[2],v[3]);
        end
    end

    if gDetector.addSSLCnamePattern then
        for i,v in ipairs(gSSLHostPatternList) do
            gDetector:addSSLCnamePattern(v[1],v[2],v[3]);
        end
    end

    return gDetector;
end

function DetectorClean()
end



