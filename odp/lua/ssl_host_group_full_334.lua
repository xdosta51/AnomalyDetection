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
detection_name: SSL Group Full "334"
version: 3
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'ImageShack' => 'Image hosting website.',
          'Office 365' => 'Traffic generated by MS Office 365 applications and web services.',
          'Shutterstock' => 'Online collection of Stock photographs and illustrations.',
          'Bluehost' => 'Web hosting portal.',
          'Bet365' => 'Online gambling website.',
          'WebEx' => 'Cisco\'s online meeting and web conferencing application.',
          'Apple Store' => 'Official online retailer of Apple products.',
          'Discover' => 'Financial services company.',
          'wikidot' => 'Site that provides wikis.',
          'Hola' => 'An open source VPN.',
          'Bloomberg' => 'Financial news and research.',
          'Samsung' => 'Electronics retail site.',
          'Nintendo' => 'Content delivery and web traffic from Nintendo, a Japanese company.',
          'Ubuntu' => 'Official website of Ubuntu.',
          'Pubmatic' => 'Web advertisement services.',
          'ZenMate' => 'Proxy and security add-on to browser.',
          'Sourceforge' => 'Site for sharing open source software projects.',
          'GMX Mail' => 'German based webmail service.',
          'Apple News' => 'Apple News is an app the brings news and magazines, all in one place.',
          'Walmart' => 'Discount department store.',
          'QQ Mail' => 'Tencent email service.',
          'Showbox' => 'Mobile application providing streaming video content.',
          'Smartsheet' => 'Smartsheet is a platform for organizational achievement.',
          'Ngrok' => 'Multiplatform tunnelling, reverse proxy software.',
          'Neustar Information Services' => 'Advertisement site.',
          'BioDigital Human' => 'A web-based medical imaging app.',
          'eBay' => 'An online auction and shopping website.',
          'Ballina Beach Village' => 'Website for a vacation resort where you can book and plan your trip to them.',
          'The Pirate Bay' => 'BitTorrent index and search engine.',
          'Azure cloud portal' => 'Microsoft Azure cloud service portal.',
          'Ooyala' => 'Solution providers for Video analytics.',
          'Office Mobile' => 'Microsoft productivty apps for use on Android devices.',
          'Symantec System Center' => 'Anti-virus software management.',
          'Google' => 'Traffic generated by the Google search engine or one of the other many Internet services provided by Google Inc.',
          'QQ Games' => 'Multi-Player online game by QQ.',
          'Integral Ad Science' => 'Advertisement site.',
          'Sears' => 'Department store retailer.',
          'EA Download Manager' => 'Electronic Arts Download manager is a digital distribution for EA games.',
          'Microsoft Azure' => 'Cloud computing by Microsoft.',
          'Freelancer' => 'Site for job listings for temporary work.',
          'Apple Music' => 'Internet radio by Apple.',
          'Narratiive' => 'Advertisement site.',
          'Twinkl' => 'Official website for Twinkl educational resources.',
          'Wordpress' => 'An online blogging community.',
          'Funshion' => 'Chinese site for online games, videos, and shopping.',
          'RealVNC' => 'A VNC package that supports client and server side, and also provides cloud-based services such as chat and file transfer.',
          'Naverisk' => 'Cloud-based remote monitoring and management software.',
          'E*TRADE' => 'Financial services company with a focus on online stock brokerage.',
          'Casale' => 'Advertisement site.',
          'Launchpad' => 'Web based bug tracking and project management tool.',
          'GitHub' => 'Code management portal for open Source projects.',
          'Telegram' => 'Telegram is a messaging app with a focus on speed and security.',
          'iCloud' => 'Apple cloud storage service.',
          'AnyDesk' => 'Remote Desktop Access Software.',
          'Kickass Torrents' => 'Torrent site.',
          'Prime Video' => 'Amazon video streaming site.',
          'DeNA websites' => 'Traffic generated by browsing DeNA Comm website and some other sites that belong to DeNA.',
          'Mercado Livre' => 'Brazil online auction and shopping website.',
          'Tus Files' => 'File upload/download site.',
          'Citi' => 'Financial services company.',
          'Amazon' => 'Online retailer of books and most other goods.',
          'TweetDeck' => 'Dashboard application to manage both Twitter and Facebook.',
          'Atlassian' => 'Project Control and Management Software.',
          'Dropbox' => 'Cloud based file storage.',
          'Apple sites' => 'Apple corporate websites.',
          'Microsoft Visual Studio' => 'Microsoft Integrated Developer Environment and toolchain designed to make it easier to develop software for Microsoft platforms.',
          'Sway' => 'Microsoft collaboration tool.',
          'American Airlines' => 'Airline services and travel planner.',
          'USPS' => 'US Postal Service website.',
          'Square Inc.' => 'Electronic payment service through mobile phones.',
          'Redbox' => 'Online movie rental and video streaming.',
          'Motley Fool' => 'Financial and Investment community.',
          'AT&T' => 'Telecom and Internet provider.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_full_334",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gSSLHostPatternList = {
    -- ZenMate
    {0, 3994, 'cuevas-navy.ml',},
    {0, 3994, 'martinez-white.ml',},
    {0, 3994, 'salinas-best-silver.ml',},
    {0, 3994, 'woodward-yellow.ml',},
    {0, 3994, 'evans-lime.ml',},
    {0, 3994, 'mitchell-gonzales-gray.ml',},
    {0, 3994, 'west-green.ml',},
}

gSSLCnamePatternList = {
    -- AT&T
    {0, 1380, 'att.net'},
    -- Aggregate Knowledge
    -- Amazon
    -- {0, 24, 'images-na.ssl-images-amazon.com'},
    {0, 24, 'peg.a2z.com'},
    -- American Airlines
    {0, 2178, 'www.aa.com'},
    -- AnyDesk
    {0, 4145, 'anydesk.cz'},
    {0, 4145, 'anydesk.de'},
    {0, 4145, 'anydesk.dk'},
    {0, 4145, 'anydesk.es'},
    {0, 4145, 'anydesk.fr'},
    {0, 4145, 'anydesk.gr'},
    {0, 4145, 'anydesk.it'},
    {0, 4145, 'anydesk.pl'},
    {0, 4145, 'anydesk.pt'},
    {0, 4145, 'anydesk.se'},
    {0, 4145, 'anydesk.sk'},
    -- Apple Music
    -- {0, 2669, 'albert.apple.com'},
    {0, 2669, 'itsliveradio.apple.com'},
    {0, 2669, 'applemusic.com'},
    {0, 2669, 'streamingaudio.itunes.apple.com'},
    {0, 2669, 'play.itunes.apple.com'},
    -- Apple News
    {0, 4623, 'news-events.apple.com',},
    {0, 4623, 'news-edge.apple.com',},
    -- Apple Store
    {0, 551, 'ppq.apple.com'},
    {0, 551, 'apptrailers.itunes.apple.com'},
    {0, 551, 'apptrailers-ssl.itunes.apple.com'},
    {0, 551, 'downloaddispatch.itunes.apple.com'},
    {0, 551, 'app-site-association.cdn-apple.com'},
    {0, 551, 'store.storeimages.cdn-apple.com'},
    -- Apple sites
    {0, 1185, 'imacsources.com'},
    -- {0, 1185, 'cups.org'},
    -- Atlassian
    {0, 2038, 'atlassian.net'},
    -- Azure cloud portal
    {0, 4533, 'azureexpertprod.westeurope.cloudapp.azure.com'},
    {0, 4533, 'cus.rp.core.security.azure.com'},
    {0, 4533, 'fpt.microsoft.com'},
    {0, 4533, 'functions.azure.com'},
    {0, 4533, 'gallery.azure.com'},
    {0, 4533, 'hosting.portal.azure.net'},
    {0, 4533, 'management.azure.com'},
    -- Ballina Beach Village
    {0, 4610, 'www.ballinabeachvillage.com.au'},
    -- Bet365
    {0, 1209, 'www.bet365careers.com'},
    -- Bing Maps
    -- BioDigital Human
    {0, 1595, 'biodigital.com'},
    -- Bloomberg
    {0, 1259, 'bloomberg.net'},
    {0, 1259, 'bloomberg.tv'},
    {0, 1259, 'bloombergbriefs.com'},
    {0, 1259, 'bloombergtradebook.com'},
    {0, 1259, 'bloombergview.com'},
    {0, 1259, 'businessweek.com'},
    {0, 1259, 'origin.bnef.com'},
    {0, 1259, 'www.bgov.com'},
    {0, 1259, 'www.bloomberglaw.com'},
    {0, 1259, 'www.bna.com'},
    -- Bluehost
    {0, 2764, 'bluehost-cdn.com'},
    -- Casale
    {0, 2512, 'medianet.com'},
    -- Citi
    {0, 590, 'citi.bridgetrack.com'},
    {0, 590, 'www.citibank.com'},
    -- DeNA websites
    {0, 2946, 'applizemi.com'},
    {0, 2946, 'arukikata.com'},
    {0, 2946, 'aumall.jp'},
    {0, 2946, 'chirashiru.jp'},
    {0, 2946, 'dena.jp'},
    {0, 2946, 'estar.jp'},
    {0, 2946, 'm.mbok.jp'},
    {0, 2946, 'mangabox.me'},
    {0, 2946, 'mycode.jp'},
    {0, 2946, 'netsea.jp'},
    {0, 2946, 'showroom-live.com'},
    {0, 2946, 'smcb.jp'},
    {0, 2946, 'sougouhoken.jp'},
    {0, 2946, 'ssl.mbga.jp'},
    {0, 2946, 'www.dena-ec.com'},
    -- Discover
    {0, 615, 'www.discovercard.com'},
    -- Dropbox
    {0, 125, 'cfl.dropboxstatic.com'},
    {0, 125, 'dl.dropboxusercontent.com'},
    -- E*TRADE
    {0, 621, 'wsod.com'},
    -- EA Download Manager
    {0, 4016, 'avatar.dm.origin.com'},
    {0, 4016, 'groups.gameservices.ea.com'},
    -- ESTsoft
    -- Freelancer
    {0, 2483, 'freelancer.co.id'},
    {0, 2483, 'freelancer.com.al'},
    {0, 2483, 'freelancer.ie'},
    {0, 2483, 'freelancer.pk'},
    -- Funshion
    {0, 2391, 'fun.tv'},
    -- GMX Mail
    -- {0, 2892, 'gmx.co.uk'},
    -- {0, 2892, 'gmx.com'},
    -- GitHub
    {0, 1670, 'githubapp.com'},
    -- Google
    {0, 184, 'google.ac'},
    {0, 184, 'google.ad'},
    {0, 184, 'google.ae'},
    {0, 184, 'google.al'},
    {0, 184, 'google.am'},
    {0, 184, 'google.as'},
    {0, 184, 'google.at'},
    {0, 184, 'google.az'},
    {0, 184, 'google.ba'},
    {0, 184, 'google.be'},
    {0, 184, 'google.bf'},
    {0, 184, 'google.bg'},
    {0, 184, 'google.bi'},
    {0, 184, 'google.bj'},
    {0, 184, 'google.bs'},
    {0, 184, 'google.bt'},
    {0, 184, 'google.ca'},
    {0, 184, 'google.cat'},
    {0, 184, 'google.cc'},
    {0, 184, 'google.cd'},
    {0, 184, 'google.cf'},
    {0, 184, 'google.cg'},
    {0, 184, 'google.ch'},
    {0, 184, 'google.ci'},
    {0, 184, 'google.cl'},
    {0, 184, 'google.cm'},
    {0, 184, 'google.co.ao'},
    {0, 184, 'google.co.bw'},
    {0, 184, 'google.co.ck'},
    {0, 184, 'google.co.cr'},
    {0, 184, 'google.co.hu'},
    {0, 184, 'google.co.id'},
    {0, 184, 'google.co.il'},
    {0, 184, 'google.co.im'},
    {0, 184, 'google.co.je'},
    {0, 184, 'google.co.jp'},
    {0, 184, 'google.co.ke'},
    {0, 184, 'google.co.kr'},
    {0, 184, 'google.co.ls'},
    {0, 184, 'google.co.ma'},
    {0, 184, 'google.co.mz'},
    {0, 184, 'google.co.nz'},
    {0, 184, 'google.co.th'},
    {0, 184, 'google.co.tz'},
    {0, 184, 'google.co.ug'},
    {0, 184, 'google.co.uk'},
    {0, 184, 'google.co.uz'},
    {0, 184, 'google.co.ve'},
    {0, 184, 'google.co.vi'},
    {0, 184, 'google.co.za'},
    {0, 184, 'google.co.zm'},
    {0, 184, 'google.co.zw'},
    {0, 184, 'google.com.af'},
    {0, 184, 'google.com.ag'},
    {0, 184, 'google.com.ai'},
    {0, 184, 'google.com.ar'},
    {0, 184, 'google.com.au'},
    {0, 184, 'google.com.bd'},
    {0, 184, 'google.com.bh'},
    {0, 184, 'google.com.bn'},
    {0, 184, 'google.com.bo'},
    {0, 184, 'google.com.br'},
    {0, 184, 'google.com.by'},
    {0, 184, 'google.com.bz'},
    {0, 184, 'google.com.co'},
    {0, 184, 'google.com.cu'},
    {0, 184, 'google.com.cy'},
    {0, 184, 'google.com.do'},
    {0, 184, 'google.com.ec'},
    {0, 184, 'google.com.eg'},
    {0, 184, 'google.com.et'},
    {0, 184, 'google.com.fj'},
    {0, 184, 'google.com.ge'},
    {0, 184, 'google.com.gh'},
    {0, 184, 'google.com.gi'},
    {0, 184, 'google.com.gt'},
    {0, 184, 'google.com.hk'},
    {0, 184, 'google.com.iq'},
    {0, 184, 'google.com.jm'},
    {0, 184, 'google.com.jo'},
    {0, 184, 'google.com.kh'},
    {0, 184, 'google.com.kw'},
    {0, 184, 'google.com.lb'},
    {0, 184, 'google.com.ly'},
    {0, 184, 'google.com.mm'},
    {0, 184, 'google.com.mt'},
    {0, 184, 'google.com.mx'},
    {0, 184, 'google.com.my'},
    {0, 184, 'google.com.na'},
    {0, 184, 'google.com.nf'},
    {0, 184, 'google.com.ng'},
    {0, 184, 'google.com.ni'},
    {0, 184, 'google.com.np'},
    {0, 184, 'google.com.nr'},
    {0, 184, 'google.com.om'},
    {0, 184, 'google.com.pa'},
    {0, 184, 'google.com.pe'},
    {0, 184, 'google.com.pg'},
    {0, 184, 'google.com.ph'},
    {0, 184, 'google.com.pk'},
    {0, 184, 'google.com.pr'},
    {0, 184, 'google.com.py'},
    {0, 184, 'google.com.qa'},
    {0, 184, 'google.com.ru'},
    {0, 184, 'google.com.sa'},
    {0, 184, 'google.com.sb'},
    {0, 184, 'google.com.sg'},
    {0, 184, 'google.com.sl'},
    {0, 184, 'google.com.sv'},
    {0, 184, 'google.com.tj'},
    {0, 184, 'google.com.tn'},
    {0, 184, 'google.com.tr'},
    {0, 184, 'google.com.tw'},
    {0, 184, 'google.com.ua'},
    {0, 184, 'google.com.uy'},
    {0, 184, 'google.com.vc'},
    {0, 184, 'google.com.vn'},
    {0, 184, 'google.cv'},
    {0, 184, 'google.cz'},
    {0, 184, 'google.de'},
    {0, 184, 'google.dj'},
    {0, 184, 'google.dk'},
    {0, 184, 'google.dm'},
    {0, 184, 'google.dz'},
    {0, 184, 'google.ee'},
    {0, 184, 'google.es'},
    {0, 184, 'google.fi'},
    {0, 184, 'google.fm'},
    {0, 184, 'google.fr'},
    {0, 184, 'google.ga'},
    {0, 184, 'google.gg'},
    {0, 184, 'google.gl'},
    {0, 184, 'google.gm'},
    {0, 184, 'google.gp'},
    {0, 184, 'google.gr'},
    {0, 184, 'google.gy'},
    {0, 184, 'google.hn'},
    {0, 184, 'google.hr'},
    {0, 184, 'google.ht'},
    {0, 184, 'google.ie'},
    {0, 184, 'google.is'},
    {0, 184, 'google.it'},
    {0, 184, 'google.kg'},
    {0, 184, 'google.ki'},
    {0, 184, 'google.kz'},
    {0, 184, 'google.la'},
    {0, 184, 'google.li'},
    {0, 184, 'google.lk'},
    {0, 184, 'google.lt'},
    {0, 184, 'google.lu'},
    {0, 184, 'google.lv'},
    {0, 184, 'google.md'},
    {0, 184, 'google.me'},
    {0, 184, 'google.mg'},
    {0, 184, 'google.mk'},
    {0, 184, 'google.ml'},
    {0, 184, 'google.mn'},
    {0, 184, 'google.ms'},
    {0, 184, 'google.mu'},
    {0, 184, 'google.mv'},
    {0, 184, 'google.mw'},
    {0, 184, 'google.ne'},
    {0, 184, 'google.net'},
    {0, 184, 'google.nl'},
    {0, 184, 'google.no'},
    {0, 184, 'google.nu'},
    {0, 184, 'google.pl'},
    {0, 184, 'google.pn'},
    {0, 184, 'google.ps'},
    {0, 184, 'google.pt'},
    {0, 184, 'google.ro'},
    {0, 184, 'google.rs'},
    {0, 184, 'google.rw'},
    {0, 184, 'google.sc'},
    {0, 184, 'google.se'},
    {0, 184, 'google.sh'},
    {0, 184, 'google.si'},
    {0, 184, 'google.sk'},
    {0, 184, 'google.sm'},
    {0, 184, 'google.sn'},
    {0, 184, 'google.so'},
    {0, 184, 'google.sr'},
    {0, 184, 'google.st'},
    {0, 184, 'google.td'},
    {0, 184, 'google.tg'},
    {0, 184, 'google.tk'},
    {0, 184, 'google.tl'},
    {0, 184, 'google.tm'},
    {0, 184, 'google.to'},
    {0, 184, 'google.tt'},
    {0, 184, 'google.vg'},
    {0, 184, 'google.vu'},
    {0, 184, 'google.ws'},
    {0, 184, 'ggpht.com'},
    -- Hola
    {0, 4041, 'h-vpn.org'},
    {0, 4041, 'holacdn.com'},
    {0, 4041, 'holaspark.com'},
    {0, 4041, 'lum-bext.com'},
    {0, 4041, 'lum-cn.co'},
    {0, 4041, 'lum-cn.io'},
    {0, 4041, 'lum-lpm.com'},
    {0, 4041, 'luminati-china.biz'},
    {0, 4041, 'luminati-china.co'},
    {0, 4041, 'luminati-china.io'},
    {0, 4041, 'luminati.io'},
    {0, 4041, 'lumtest.com'},
    {0, 4041, 'svd-cdn.com'},
    -- ImageShack
    {0, 682, 'imageshack.us'},
    -- Integral Ad Science
    {0, 2532, 'integralplatform.com'},
    -- Kickass Torrents
    {0, 3870, 'katcr.co'},
    {0, 3870, 'kickass.cr'},
    {0, 3870, 'kickass.la'},
    -- Launchpad
    {0, 708, 'launchpadlibrarian.net'},
    -- Mercado Livre
    {0, 2860, 'mercadolibre.cl'},
    {0, 2860, 'mercadolibre.co.cr'},
    {0, 2860, 'mercadolibre.com.ar'},
    {0, 2860, 'mercadolibre.com.co'},
    {0, 2860, 'mercadolibre.com.do'},
    {0, 2860, 'mercadolibre.com.ec'},
    {0, 2860, 'mercadolibre.com.mx'},
    {0, 2860, 'mercadolibre.com.pa'},
    {0, 2860, 'mercadolibre.com.pe'},
    {0, 2860, 'mercadolibre.com.uy'},
    {0, 2860, 'mercadolibre.com.ve'},
    {0, 2860, 'mercadolivre.com.br'},
    {0, 2860, 'mercadoshops.com.br'},
    {0, 2860, 'mercadolibre.com'},
    {0, 2860, 'www.mercadopago.com.br'},
    {0, 2860, 'www.mercadopago.com'},
    -- Microsoft Azure
    {0, 2111, 'azure.microsoft.com'},
    {0, 2111, 'policykeyservice.dc.ad.msft.net'},
    {0, 2111, 'secure.aadcdn.microsoftonline-p.com'},
    {0, 2111, 'windowsazure.com'},
    -- Microsoft CRM Dynamics
    -- Microsoft Visual Studio
    {0, 3979, 'vortex.data.microsoft.com'},
    -- Motley Fool
    {0, 2863, 'fool.ca'},
    {0, 2863, 'fool.co.uk'},
    {0, 2863, 'fool.com.au'},
    {0, 2863, 'fool.sg'},
    -- Narratiive
    {0, 2516, 'effectivemeasure.com'},
    -- Naverisk
    {0, 2390, 'ecisolutions.com'},
    -- Neustar Information Services
    {0, 2537, 'neustarlocaleze.biz'},
    -- Ngrok
    {0, 4134, 'ngrok.io'},
    -- Nintendo
    {0, 4130, 'nintendo-europe.com'},
    {0, 4130, 'nintendo.co.kr'},
    {0, 4130, 'nintendo.se'},
    -- Office 365
    -- {0, 2812, 'msocdn.com'},
    {0, 2812, 'stamp2.login.microsoftonline.com'},
    {0, 2812, 'support.microsoft.com'},
    {0, 2812, 'testconnectivity.microsoft.com'},
    {0, 2812, 'videobreakdown.com'},
    {0, 2812, 'wildcard.onestore.ms'},
    -- Office Mobile
    {0, 4072, 'appex-rf.msn.com'},
    {0, 4072, 'msagfx.live.com'},
    {0, 4072, 'msft.sts.microsoft.com'},
    -- Ooyala
    {0, 2072, 'www.dalet.com'},
    -- PayPal
    -- {0, 1134, 'www.paypal.com'},
    -- Prime Video
    {0, 3793, 'api.us-east-1.aiv-delivery.net'},
    {0, 3793, 'atv-ext-eu.amazon.com'},
    {0, 3793, 'atv-ps.amazon.com'},
    {0, 3793, 'dp-gw-na.amazon.com'},
    -- Pubmatic
    {0, 1315, 'www.pubmatic.co.jp'},
    -- QQ Games
    {0, 3727, 'minigame.qq.com'},
    {0, 3727, 'oct01.sparta.3g.qq.com'},
    -- QQ Mail
    {0, 3882, 'exmail.qq.com'},
    {0, 3882, 'pop.qq.com'},
    -- RealVNC
    {0, 4142, 'vnc.com'},
    -- Redbox
    {0, 1830, 'ojrq.net'},
    -- Samsung
    {0, 1357, 'samsungapps.com'},
    -- Sears
    {0, 821, 'searshomepro.com'},
    {0, 821, 'searshomeservices.com'},
    {0, 821, 'searsoptical.com'},
    {0, 821, 'searspartsdirect.com'},
    {0, 821, 'searsvacations.com'},
    {0, 821, 'www.kenmoredirect.com'},
    {0, 821, 'www.searsdrivingschools.com'},
    {0, 821, 'www.searsflowers.com'},
    -- Showbox
    -- {0, 4149, '10bo.365zg.org'},
    {0, 4149, 'showboxdownload.site'},
    -- Shutterstock
    {0, 1614, 'stockphotoeditor.com'},
    -- Smartsheet
    {0, 4621, 'app.10000ft.com'},
    -- Sourceforge
    {0, 1177, 'sf.net'},
    -- Square Inc.
    {0, 1568, 'www.squareup.com'},
    -- Sway
    {0, 4069, 'c.msn.com'},
    {0, 4069, 'www.sway-cdn.com'},
    -- Symantec System Center
    {0, 459, 'www.broadcom.com'},
    -- Telegram
    {0, 4116, 'telegram.me'},
    {0, 4116, 'telegram.org'},
    -- Tencent Cloud
    -- The Pirate Bay
    {0, 1136, 'hcpes.me'},
    {0, 1136, 'offlinebay.com'},
    {0, 1136, 'onion.ly'},
    {0, 1136, 'parkingcrew.net'},
    {0, 1136, 'pirateaccess.xyz'},
    {0, 1136, 'pirateproxy.party'},
    {0, 1136, 'pirateproxy.site'},
    {0, 1136, 'proxybay.club'},
    {0, 1136, 'thebay.tv'},
    {0, 1136, 'thehiddenbay.info'},
    {0, 1136, 'thepiratebay-org.prox.icu'},
    {0, 1136, 'thepiratebay.blue'},
    {0, 1136, 'thepiratebay.fyi'},
    {0, 1136, 'thepiratebay2.se'},
    {0, 1136, 'thepiratebay2.unblocked.ms'},
    {0, 1136, 'tpb.run'},
    {0, 1136, 'tpb.tw'},
    {0, 1136, 'ukpirate.org'},
    -- Tus Files
    {0, 4515, 'tusfiles.net'},
    -- TweetDeck
    {0, 1360, 'tweetdeck.twitter.com'},
    -- Twinkl
    {0, 4608, 'www.twinkl.co.uk'},
    -- USPS
    {0, 1601, 'www.uspspostalone.com'},
    -- Ubuntu
    {0, 2003, '360.canonical.com'},
    -- Walmart
    {0, 901, 'prod.walmart.ca'},
    -- WebEx
    {0, 905, 'files-prod-us-east-2.webexcontent.com'},
    {0, 977, 'gmx.at'},
    {0, 977, 'gmx.ch'},
    {0, 977, 'gmx.net'},
    {0, 977, 'gmx.co.uk'},
    -- Wordpress
    {0, 506, 'wp.com'},
    -- ZenMate
    {0, 3994, 'zenguard.zendesk.com'},
    {0, 3994, 'cuevas-navy.ml',},
    {0, 3994, 'martinez-white.ml',},
    {0, 3994, 'salinas-best-silver.ml',},
    {0, 3994, 'woodward-yellow.ml',},
    {0, 3994, 'evans-lime.ml',},
    {0, 3994, 'mitchell-gonzales-gray.ml',},
    {0, 3994, 'west-green.ml',},
    -- eBay
    {0, 132, 'ebaykorea.com'},
    -- {0, 132, 'epages.ebay.com'},
    {0, 132, 'shipping.ebay.cn'},
    {0, 132, 'www.ebay.co.jp'},
    -- iCloud
    {0, 1187, 'americasred3.apple.com'},
    {0, 1187, 'catch-trunk.com'},
    -- wikidot
    {0, 2352, 'wdfiles.com'},
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance

    if gDetector.addSSLCertPattern then
        for i,v in ipairs(gSSLHostPatternList) do
            gDetector:addSSLCertPattern(v[1],v[2],v[3]);
        end
    end


    if gDetector.addSSLCnamePattern then
        for i,v in ipairs(gSSLCnamePatternList) do
            gDetector:addSSLCnamePattern(v[1],v[2],v[3]);
        end
    end

    return gDetector;
end

function DetectorClean()
end

