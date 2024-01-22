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
detection_name: SSL Group "Vanilla Ice"
version: 12
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Quora' => 'Online discussion forums on a wide variety of topics.',
          'Eyejot' => 'Video mail web application.',
          'LeapFILE' => 'Managed file transfer site.',
          'Megaproxy' => 'Web VPN services through SSL traffic.',
          'eRoom' => 'Collaborative software site.',
          'Guardster' => 'Anonymous proxy service.',
          'Wii' => 'Video games console by Nintendo.',
          'CrossLoop' => 'Desktop sharing / remote access site.',
          'Hangame' => 'Korean online game portal.',
          'Bloglovin' => 'Blog portal.',
          'Fluxiom' => 'Cloud storage, collaboration, and file management.',
          'Okurin' => 'Japanese file upload site.',
          'Yahoo! Mobage' => 'Mobile gaming platform popular in Japan.',
          'DuckDuckGo' => 'Search engine.',
          'Twiddla' => 'Web based collaboration tool.',
          'KProxy' => 'Anonymous proxy service.',
          'Fetion' => 'Chinese instant messaging client.',
          'Shopkick' => 'Mobile app for shopping.',
          'Fotki' => 'Photo sharing site.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_vanilla_ice",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--detectorType(0-> Web, 1->Client),  AppId, SSLPattern
gSSLHostPatternList = {

    -- Eyejoy
    { 0, 2803, 'eyejot.com' },
    -- DuckduckGo
    { 0, 2805, 'duckduckgo.com' },
    -- Fetion
    { 0, 2817, 'fetionpic.com' },
    -- Fluxiom
    { 0, 2818, 'fluxiom.com' },
    -- GigaUP
    -- { 0, 2819, 'gigaup.fr' },
    -- LeapFILE
    { 0, 2820, 'leapfile.net' },
    -- Netload
    -- { 0, 2821, 'netload.in' }, 
    -- Okurin
    { 0, 2822, 'bitpark.co.jp' },
    -- Fotki
    { 0, 2824, 'fotki.com' },
    -- CrossLoop
    { 0, 2825, 'crossloop.com' },
    -- eRoom
    { 0, 2826, 'eroom.com' },
    { 0, 2826, 'eroom.net' },
    -- Wii
    { 0, 2830, 'wii.com' },
    -- Shopkick 
    { 1, 2831, 'shopkick.com' },
    -- Hangame  
    { 0, 2832, 'hangame.co.kr' },
    { 0, 2832, 'hangame.com' },
    -- Megaproxy
    { 0, 2834, 'megaproxy.com' },
    -- KProxy
    { 0, 2835, 'kproxy.com' },
    -- Guardster
    { 0, 2836, 'guardster.com' },
    -- Twiddla
    { 0, 2841, 'twiddla.com' },
    -- -- Aereo
    -- { 0, 2842, 'aereo.com' },
    -- Quora
    { 0, 2843, 'quora.com' },
    { 0, 2843, 'insnw.net' },
    { 0, 2843, 'quoracdn.net' },
    -- Yahoo! Mobage
    { 0, 2844, 'yahoo-mbga.jp' },
    -- Bloglovin
    { 0, 2867, 'bloglovin.com' },
}


function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.addSSLCertPattern then
        for i,v in ipairs(gSSLHostPatternList) do
            gDetector:addSSLCertPattern(v[1],v[2],v[3]);
        end
    end
    return gDetector;
end

function DetectorClean()
end
