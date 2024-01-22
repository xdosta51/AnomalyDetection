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
detection_name: SSL Group "Belvedere"
version: 65
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'KakaoTalk' => 'Mobile messaging for smartphones.',
          'Snapchat' => 'Online photo sharing.',
          'USPS' => 'US Postal Service website.',
          'Urban Airship' => 'Mobile app developer.',
          'Google Remote Desktop' => 'Online desktop sharing service.',
          'Etsy' => 'E-commerce website for homemade or vintage items.',
          'Avaya Live' => 'Cloud based VoIP service.',
          'PayPal' => 'E-commerce website for handling online transactions.',
          'Rediff.com' => 'Online news, information and web portal.',
          'Zynga' => 'Social network game developer.',
          'American Express' => 'Financial services company.',
          'Mint.com' => 'Web-based personal finance tool.',
          'Citi' => 'Financial services company.',
          'Outbrain' => 'Online help for publishers and bloggers.',
          'Livedoor' => 'Japanese Internet service provider.',
          'Taringa' => 'Argentinian Social network.',
          'Siri' => 'Voice interactive agent for Apple\'s iOS.',
          'Wells Fargo' => 'Global financial services company.',
          'Evernote' => 'Synched note taking and web bookmarking app.',
          'Comcast' => 'Web Portal.',
          'Capital One' => 'U.S. based bank holding company.',
          'Gmail' => 'Google online email.',
          'IMRWorldWide' => 'Market research and Network analytics to display advertisement.',
          'Geewa' => 'Browser and Facebook-based gaming.',
          'UOL' => 'Brazilian web portal for news and entertainment.',
          'Aliexpress' => 'Online shopping portal.',
          'Doubleclick' => 'Web advertisement services.',
          'Shutterstock' => 'Online collection of Stock photographs and illustrations.',
          '500px' => 'Online photo sharing.',
          'Spiegel Online' => 'Web portal for the Germans magazine Der Speigel.',
          'Flurry Analytics' => 'Mobile application analytics.',
          'iTunes' => 'Apple\'s media player and online store.',
          'BioDigital Human' => 'A web-based medical imaging app.',
          'Yieldmanager' => 'Online advertising delivery portal.',
          'Airbnb' => 'Online accommodation rental service.',
          'Discover' => 'Financial services company.',
          'HSBC' => 'Global banking and financial services company.',
          'ZEDO' => 'Web advertisement services.',
          '58 City' => 'Classified information about 58 cities in China.',
          'Instagram' => 'Mobile phone photo sharing.',
          'DoubleDownCasino' => 'Facebook casino games.',
          'Odnoklassniki' => 'Russian social networking service.',
          'Google' => 'Traffic generated by the Google search engine or one of the other many Internet services provided by Google Inc.',
          'U.S.Bank' => 'Online banking web portal for U.S Bank.',
          'Dwolla' => 'Online Payment service.',
          'Pinterest' => 'Social photo sharing website.',
          'Bubble Saga' => 'Facebook bubble bursting game.',
          'CSDN' => 'Chinese IT community/forum for Software related issues.',
          'Square Inc.' => 'Electronic payment service through mobile phones.',
          'Jingdong (360buy.com)' => 'Chinese e-commerce site.',
          'Bank of America' => 'Global financial services company.',
          'Airtime' => 'Video chat.',
          'LivingSocial' => 'Deals website.',
          'Apple Developer' => 'Web portal for Apple Developer.',
          'Shutterfly' => 'Share, prints and personalize the cards, album, mugs and other Home decor items with your photos.',
          'Akamai' => 'Internet content delivery network and SSL certificate provider.',
          'The Guardian' => 'Online news portal.',
          'Amazon Web Services' => 'Online cloud computing service.',
          'Dailymotion' => 'A video sharing service website.',
          'Loyalty Innovations' => 'Reward programs and solutions for both online and offline.',
          'Symantec System Center' => 'Anti-virus software management.',
          'King.com' => 'Web-based gaming.',
          'Cisco Secure Endpoint' => 'Cloud-based real time antivirus protection. (AMP for Endpoints).',
          'Adcash' => 'Advertising network.',
          'Allmyapps' => 'Application update manager.',
          'The New York Times' => 'Newspaper website.',
          'E*TRADE' => 'Financial services company with a focus on online stock brokerage.',
          'Words With Friends' => 'Word game.',
          'Exchange Online' => 'Traffic associated with Exchange Online, such as visiting outlook.com.',
          'Official Major League Baseball' => 'Web Portal for Sports news update.',
          'The Telegraph' => 'Online news portal.',
          'Spotify' => 'Social Music Player.',
          'Yandex' => 'Russian search engine.',
          'Avast' => 'Anti-virus software for Windows PCs.',
          'Chase' => 'Consumer and commercial banking company.',
          'Wooga' => 'Browser and social network based games company.',
          'Rakuten' => 'Japanese e-commerce site.',
          'T Mobile' => 'Telecommunication and phone service provider.',
          'Craigslist' => 'Popular online classifieds.',
          'Naver' => 'Web portal.',
          'AOL' => 'American company develops, grows and invests in brands and web sites.',
          'BranchOut' => 'Facebook professional networking.',
          'CloudFront' => 'Content Delivery for AWS.',
          'Facebook' => 'Facebook is a social networking service.',
          'Pubmatic' => 'Web advertisement services.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "ssl_host_group_belvedere",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gSSLHostPatternList = {
	--Odnoklassniki
	{ 0, 1070, 'odnoklassniki.ru' },
	--PayPal
	{ 0, 1134, 'www.paypal.com' },
	--Pinterest
	{ 1, 1135, 'pinterest.com' },
	--Spotify
	{ 0, 1158, 'spotify.com' },
	--Words With Friends
	{ 0, 1163, 'zyngawithfriends.com' },
	--Mint.com
	{ 0, 1193, 'mint.com' },
	--Instagram
	{ 1, 1233, 'instagram.com' },
	--DoubleDownCasino
	{ 0, 1234, 'doubledowncasino.com' },
	--Bubble Saga
	{ 0, 1244, 'bubblesaga.king.com' },
	--BranchOut
	{ 0, 1250, 'branchout.com' },
	--Avast
	{ 0, 1264, 'avast.com' },
	--Allmyapps
	{ 0, 1265, 'buildyourapps.info' },
	--Evernote
	{ 0, 1267, 'www.evernote.com' },
	--Wooga
	{ 0, 1298, 'wooga.com' },
	--The New York Times
	{ 0, 1299, 'nytimes.com' },
	--Naver
	{ 0, 1309, 'naver.com' },
	--Advertising.com
	--{ 0, 1310, 'advertising.com' },
	--Doubleclick
	{ 0, 1313, 'doubleclick.net' },
	--Pubmatic
	{ 0, 1315, 'pubmatic.com' },
	--ZEDO
	{ 0, 1362, 'zedo.com' },
	--Comcast
	{ 0, 1365, 'comcast.com' },
	--Outbrain
	{ 0, 1369, 'www.outbrain.com' },
	--Etsy
	{ 0, 1374, 'etsy.com' },
	--Official Major League Baseball
	{ 0, 1385, 'mlb.com' },
	--Amazon Web Services
	{ 0, 1392, 's3-external-1.amazonaws.com' },
	--CloudFront
	{ 0, 1393, 'cloudfront.net' },
	--KakaoTalk
	{ 1, 1405, 'kakao.com' },
	--Flurry Analytics
	{ 0, 1406, 'flurry.com' },
	--AOL
	{ 0, 1419, 'aol.com' },
	--LivingSocial
	{ 0, 1495, 'livingsocial.com' },
	--U.S.Bank
	{ 0, 1500, 'usbank.tt.omtrdc.net' },
	--Shutterfly
	{ 0, 1543, 'shutterfly.com' },
	--T Mobile
	{ 0, 1545, 't-mobile.com' },
	--IMRWorldWide
	{ 0, 1560, 'imrworldwide.com' },
	--Square Inc.
	{ 0, 1568, 'squareup.com' },
	--BioDigital Human
	{ 0, 1595, 'biodigitalhuman.com' },
	--Apple Developer
	{ 0, 1596, 'developer.apple.com' },
	--Geewa
	{ 0, 1597, 'geewa-cdn.com' },
	--King.com
	{ 0, 1599, 'Midasplayer.com' },
	--USPS
	{ 0, 1601, 'usps.com' },
	--Siri
	{ 0, 1603, 'guzzoni.apple.com' },
	--Shutterstock
	{ 0, 1614, 'shutterstock.com' },
	--Yandex
	{ 0, 1616, 'yandex.by' },
	--Adcash
	{ 0, 1617, 'adcash.com' },
	--The Guardian
	{ 0, 1618, 'guardian.co.uk' },
	--Yieldmanager
	{ 0, 1619, 'yieldmanager.com' },
	--The Telegraph
	{ 0, 1620, 'telegraph.co.uk' },
	--Livedoor
	{ 0, 1621, 'livedoor.com' },
	--Rediff.com
	{ 0, 1624, 'rediff.com' },
	--Spiegel Online
	{ 0, 1625, 'spiegel.de' },
	--UOL
	{ 0, 1626, 'uol.com.br' },
	--Jingdong (360buy.com)
	{ 0, 1627, '360buy.com' },
	--Airtime
	{ 0, 1645, 'airtime.com' },
	--CSDN
	{ 0, 1646, 'passport.csdn.net' },
	--Taringa
	{ 0, 1647, 'taringa.net' },
	--Aliexpress
	{ 0, 1648, 'aliexpress.com' },
	--58 City
	{ 0, 1649, 'passport.58.com' },
	--Rakuten
	{ 0, 1652, 'rakuten.co.jp' },
	--Snapchat
	{ 1, 1653, 'feelinsonice.appspot.com' },
	--500px
	{ 1, 1654, '500px.com' },
	--Airbnb
	{ 0, 1655, 'airbnb.com' },
	--Invitemedia
	--{ 0, 1656, 'invitemedia.com' },
	--Urban Airship
	{ 0, 1657, 'urbanairship.com' },
	--Akamai
	{ 0, 1659, 'akamaihd.net' },
	--Loyalty Innovations
	{ 0, 1660, 'loyaltyinnovations.com' },
	--Avaya Live
	{ 1, 1661, 'avayalive.com' },
	--Dwolla
	{ 0, 1664, 'www.dwolla.com' },
	--Google Remote Desktop
	{ 1, 1665, 'chromoting-oauth.talkgadget.google.com' },
	--Google
	{ 0, 184, 'google.com' },
	--Exchange Online
	{ 0, 2810, 'res.outlook.com' },
	--Symantec System Center
	{ 0, 459, 'symantec.com' },
	--Zynga
	{ 0, 533, 'zgncdn.com' },
	--American Express
	{ 0, 544, 'www.aexp-static.com' },
	--Bank of America
	{ 0, 560, 'bankofamerica.com' },
	--Capital One
	{ 0, 582, 'capitalone.com' },
	--Chase
	{ 0, 587, 'chase.com' },
	--Citi
	{ 0, 590, 'citibank.com' },
	--Craigslist
	{ 0, 594, 'craigslist.org' },
	--Dailymotion
	{ 0, 600, 'dailymotion.com' },
	--Discover
	{ 0, 615, 'discover.com' },
	--E*TRADE
	{ 0, 621, 'etrade.com' },
	--Facebook
	{ 0, 629, 'fbcdn-photos-a.akamaihd.net' },
	--Gmail
	{ 0, 655, 'mail.google.com' },
	--HSBC
	{ 0, 675, 'hsbc.com' },
	--iTunes
	{ 0, 689, 'mzstatic.com' },
	--Wells Fargo
	{ 0, 907, 'wellsfargo.com' },
	--Cisco Secure Endpoint
	{ 1, 934, 'amp.cisco.com' },
}
gSSLCnamePatternList = {
	--DoubleDownCasino
	{ 0, 1234, 'doubledowncasino.com' },
	--Snapchat
	{ 0, 1653, 'snapchat.com' },
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance

    if gDetector.addSSLCertPattern then
        for i,v in ipairs(gSSLHostPatternList) do
            gDetector:addSSLCertPattern(v[1],v[2],v[3])
        end
    end


    if gDetector.addSSLCnamePattern then
        for i,v in ipairs(gSSLCnamePatternList) do
            gDetector:addSSLCnamePattern(v[1],v[2],v[3])
        end
    end

    return gDetector
end

function DetectorClean()
end