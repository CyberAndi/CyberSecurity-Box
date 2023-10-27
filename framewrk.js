document.addEventListener("touchstart",function(event){},true);
document.addEventListener("orientationchange",function(){fnSetOnLoad();},true);
window.onscroll = function() {fnOnScroll();}
var objBody = document.body;
var objHTML = document.documentElement;
var root = document.documentElement;
var objCreateScript = document.createElement("script");
var objCreateDiv = document.createElement("div");
var objSlideshow = document.getElementsByClassName("Slideshow");
var objMainSlideshow = document.getElementById("mainSlideshow");
var objContainerSlideshow = document.getElementsByClassName("containerSlideshow");
var objContainerSlider = document.getElementsByClassName("containerSlider");
var objContDot = document.getElementsByClassName("dotContainer");
var objBackDot = document.getElementsByClassName("dotBackground");
var objDot = document.getElementsByClassName("dot");
var objHeader = document.getElementsByClassName("header");
var objNavi = document.getElementsByClassName("Navi");
var objTitle = document.getElementsByClassName("Title");
var objPreview = document.getElementsByClassName("Preview");
var objContainerTitle = document.getElementsByClassName("PlayerOverlay");
var objSlide = document.getElementsByClassName("Slide");
var objMenu = document.getElementsByClassName("menu");
var objInfo = document.getElementsByClassName("Info");
var objInfoTXT = document.getElementsByClassName("InfoText");
var objContent = document.getElementsByClassName("Content");
var objContentText = document.getElementsByClassName('ContentText');
var objContainerOverlay = document.getElementsByClassName("containerOverlay");
var objOverlay = document.getElementsByClassName("Overlay");
var objModal = document.getElementsByClassName("modal");
var objBackground = document.getElementsByClassName("scrollPic");
var objBackGImg = document.getElementsByClassName("img");
var objMain = document.getElementById("main");
var objMovers = document.querySelectorAll(".mover");
var objFirstScriptTag = document.getElementsByTagName("script")[0];
var objYTIFrame = [];
var objYTIFrameInner = [];
var objYTMain = [];
var objScrollPic = [];
var objBibleText = [];
var objPos;
var browser = window.navigator;
var browserVersion;
var htmlVersion;
var withoutVideoHeight;
var videoHeight;
var videoMinHeight;
var contentHeight;
var backgroundCalcHeight = [];
var backgroundCalcLayerHeight = [];
var backgroundHeight = [];
var backgroundTop = [];
var backgroundPosTop = [];
var backgroundScreenTop = [];
var backgroundLayerTop = [];
var factorHDVideo = 56.25;
var factorLetterBoxVideo = 42.166875;
var overlayDiverence = [];
var overlayHeight = [];
var overlayCalcHeight = [];
var overlayCalcLayerHeight = [];
var overlayTop = [];
var overlayLayerTop = [];
var overlayHeadTop = [];
var overlayScreenTop = [];
var overlayScreenBottom = [];
var overlayBottom = [];
var overlayHeadBottom = [];
var overlayPos = [];
var overlayPosTop = [];
var overlayPosHalfTop = [];
var overlayPosOverlayTop = [];
var overlayPosScreenTop = [];
var overlayPosBottom = [];
var overlayPosHeadBottom = [];
var overlayPosScreenBottom = [];
var overlayPosHeadScreenBottom = [];
var overlayPosOverlayBottom = [];
var overlayPosHeadOverlayBottom = [];
var overlayPosHeadTop = [];
var overlayPosHeadHalfTop = [];
var overlayPosHeadOverlayTop = [];
var overlayPosHeadScreenTop = [];
var overlayPositionScreenTop = [];
var overlayPositionTop = [];
var overlayPositionBottom = [];
var overlayPositionScreenBottom = [];
var unfixedBGPosTop = []; 
var unfixedOverlayPosTop = [];
var hasSlideShow = [];
var hasSubAnimation = [];
var scrollFirst = [];
var scrollPrev = [];
var overlPos = [] ;
var countOverlay = 0;
var screenHeight = window.innerHeight;
var screenWidth = window.innerWidth;
var documentHeight;
var screenHProcent = Math.round(window.innerHeight / 100);
var screenWProcent = Math.round(window.innerWidth / 100);
var screenHvwPix = Math.round(window.innerWidth / screenWProcent);
var screenWvwPix = screenWProcent;
var fontSizePx = fnReadRootCSS('--fontSizeEm');
var fontSizeEm = fontSizePx;
var headerHeight = fontSizeEm * 9.5;
var headerHeightSmall = fontSizeEm * 4.5;
var headerHeightLarge = fontSizeEm * 9.5;
var footerHeight = fontSizeEm * 2;
var bsLogoHeight = 51; /*Bible Server Logo Height*/
var playerTmp = [];
var player;
var YTdone = false;
var screenRatio;
var screenProcent;
var scrollPic;
var scrollPosScreenTop;
var scrollPosHeaderBottom;
var scrollPosFooterTop;
var scrollPosScreenBottom;
var bibleText;
var lastScrollY = 0;
var lastScrollX = 0;
var ticking = false;
var videoPlay = 0;
var infoClose = [];
var runFade = 0;
var activeScroll = 0;
var indexPosition = 0;
var timer_on = 0;
var picDirection = 'up';
var swipeIn = true;
var swipePrev = 0;
var windowOrientation = "";
var videoHeigth = '100%';
var videoWidth = '100%';
var swipeIn = true;
var swipePrev = 0;
var originHTML = urlLocal ;
var originPort = "2050";
var originDir = "CaptivePortal";
var originFile = "index";
var originFileExtention = ".htm";
var originComplite = originHTML + ":" + originPort + "/" + originDir + "/" + originFile + originFileExtention;
var urlHTTPS = "https://";
var urlLocal = urlHTTPS + "192.168.189.1";
var urlYT_org = urlHTTPS + "www.youtube.com";
var urlYT = urlHTTPS + "invidious.nerdvpn.de";
var urlYTCookie_org = urlHTTPS + "www.youtube-nocookie.com";
var urlYTCookie = urlHTTPS + "invidious.nerdvpn.de";
var urlYTDirEmbed = "embed";
var urlYTDirWebP = "vi_webp";
var urlYTDirJpg = "vi";
var urlYTDirImg = urlHTTPS + "i.ytimg.com";
var urlVimeo = urlHTTPS + "www.vimeo.com";
var apiYT = "iframe_api";
var apiYTTitle = 'CMovie Video Player';
var apiYTPermission = 'accelerometer; encrypted-media; gyroscope; picture-in-picture';
var videoYTParam ='no_cookie=1&modestbranding=0&origin=https%3A%2F%2F192.168.189.1%3A8443&showinfo=0&playsinline=1&autoplay=0&rel=0&controls=0&enablejsapi=1&fs=0&disablekb=1&clipboard_write=0&iv_load_poliy=3&cc_load_poliy=0&encrypted_media=1&wmode=transparent&title=0&setPlaybackRate=hd1080';
var windowOrientation = "";
var runcount = 0;
var videoYTFormat = ['mqdefault',
'hqdefault',
'sddefault',
'hq720',
'maxresdefault'];
var videoYTId = [
	'FdcLKygXYAw', /*0*/
	'1G0_A2xZd8g', /*1*/
	'sAx4rUsUAdg', /*2*/
	'CL-petFZkRk', /*3*/
	'F8NFr8wI3PM', /*4*/
	'7W4LyIoXc2U', /*5*/
	'42cSOnfDlCs', /*6*/
	'7gXw4HA7PMU', /*7*/
	'5S2R3efEG64', /*8*/
	'UfB4-SHtHr4' /*9*/
];

var videoYTImg = [
	'' + urlYTDirImg  + '/' + urlYTDirJpg + '/' + videoYTId[0] + '/maxresdefault.jpg',
	'' + urlYTDirImg  + '/' + urlYTDirJpg + '/' + videoYTId[1] + '/maxresdefault.jpg',
	'' + urlYTDirImg  + '/' + urlYTDirJpg + '/' + videoYTId[2] + '/maxresdefault.jpg',
	'' + urlYTDirImg  + '/' + urlYTDirJpg + '/' + videoYTId[3] + '/maxresdefault.jpg',
	'' + urlYTDirImg  + '/' + urlYTDirJpg + '/' + videoYTId[4] + '/mqdefault.jpg',
	'' + urlYTDirImg  + '/' + urlYTDirJpg + '/' + videoYTId[5] + '/hqdefault.jpg',
	'' + urlYTDirImg  + '/' + urlYTDirJpg + '/' + videoYTId[6] + '/maxresdefault.jpg',
	'' + urlYTDirImg  + '/' + urlYTDirJpg + '/' + videoYTId[7] + '/maxresdefault.jpg',
	'' + urlYTDirImg  + '/' + urlYTDirJpg + '/' + videoYTId[8] + '/maxresdefault.jpg',
	'' + urlYTDirImg  + '/' + urlYTDirJpg + '/' + videoYTId[9] + '/maxresdefault.jpg'
];


var videoYTIdTmp = [
	'FdcLKygXYAw',
	'1G0_A2xZd8g',
	'?list=PLJ8UZqGFu6kQ8izCveCYb9e4AcDpvk1UP',
	'?list=LotharGassmann&listType=user_uploads',
	'?list=PLJ8UZqGFu6kT1Cy7f8_4UKGsDy7dE2RCy',
	'?list=PLfb-8Saw2UlP75bWUDiQCRdbcF5bz1E91',
	'?list=UUHMFLrrAnhn1HXHlwotS4uQ',
	'?list=PLXImG20e6sChZ7tAMjDX1MCKOB4cFj3N4',
	'?list=PLJ8UZqGFu6kT4pNSqSBK_76G6YzJSF852',
	'UfB4-SHtHr4'
];
var videoYTIdTitle = [
	'Krisenvorsorge von <cite>Outdoor Chiemgau</cite>'
	,'Trailer zur Serie <cite>The Chosen</cite> &uuml;ber Jesus Christus'
	,'Meine eigenen Ver&ouml;ffentlichungen'
	,'Videos und Predigten von <cite>Dr. Lothar Gassmann</cite>'
	,'Empfenswerte Videos zum Thema <cite>IT-Sicherheit, Datenschutz usw.</cite>'
	,'Die komplette erste Staffel der Serie <cite>The Chosen</cite>'
	,'COVID-Impfstoffe unter dem Mikroskop von <cite>J&ouml;rg Rinne</cite>'
	,'<cite>ICF Z&uuml;rich</cite> Gottesdienste(deutsch) mit Leo Bigger usw.'
	,'<cite>C\`Movie</cite> Lineares Programm &uuml;ber alle Kan&auml;le'
	,'<cite>Victory Channel</cite> Christliche News und Predigten aus USA'
];


var development = 0;

if (screenHProcent < screenWProcent) {
			screenProcent = screenHProcent;
			screenRatio = Math.round((screenWProcent / screenHProcent) * 1000) / 1000;
		} else {
			screenProcent = screenWProcent;
			screenRatio = Math.round((screenHProcent / screenWProcent) * 1000) / 1000;
}

	
async function fnSleep(ms) {
  		return new Promise(resolve => setTimeout(resolve, ms));
}


function fnChkBrowserVersion() {
		var TXT = browser.userAgent;
		if (TXT.indexOf('Chrome') != '-1') {
			browserVersion ='Chromium ' + TXT.substr(TXT.indexOf('Chrome')+7,6);
		} else if (TXT.indexOf('Firefox') != '-1') {
			browserVersion ='Firefox ' + TXT.substr(TXT.indexOf('Firefox')+8,6);
		} else if (TXT.indexOf('Safari') != '-1') {
			browserVersion ='Safari ' + TXT.substr(TXT.indexOf('Safari')+6,6);
		} else if (TXT.indexOf('AppleWebKit') != '-1') {
			browserVersion ='Safari ' + TXT.substr(TXT.indexOf('AppleWebKit')+12,6);
		} else {
			browserVersion = browser.userAgent;
		}
		return browserVersion;
}


async function callPlayer(func, args, inID) {
    var iframes = document.getElementsByTagName('iframe');
       if (iframes[inID]) {
            var src = iframes[inID].getAttribute('src');
            if (src) {
		
                if (src.indexOf('youtube.com') != -1 || src.indexOf('youtube-nocookie.com') != -1) {
                    iframes[inID].contentWindow.postMessage(JSON.stringify({
                        'event': 'command',
                        'func': func,
                        'args': args || []
                    }), "*");
		   
                }
            }
       
    }
}


async function fnMakeSlideshow() {
	var ayPos = 0;
	var axPos = 1;
	objSlideshow[0].innerHTML = '';
	objContainerSlider[0].innerHTML = '';
	let tmpHTML2 = '<div class="container x mandatory-snap Slideshow">\n';
	objContainerSlider[0].innerHTML += tmpHTML2;
	for (let x of videoYTIdTmp) {
		var ytPos = ayPos + 1;
		let tmpHTML = '<div class="SlideshowContent">\n';
		tmpHTML  += '\t<div id="Pos' + ytPos + '" class="Slide" sandbox="">\n';
		tmpHTML  += '\t</div>\n';
		tmpHTML  += '\t<div class="Slide Preview"></div>\n';
		if (x.indexOf('?') != '-1') {
			tmpHTML  += '\t<a class="Navi" href="' + urlYTCookie + '/' + urlYTDirEmbed + '/' + videoYTId[ytPos] + '' + x + '&' + videoYTParam + '" data-script="yes" alt="play">&#9658;\n\t\t</a>\n';
			tmpHTML  += '\t<div class="Title">\n';
			tmpHTML  += '\t\t<a href="' + urlYTCookie + '/' + urlYTDirEmbed + '/' + videoYTId[ytPos] + '' + x + '&' + videoYTParam + '" target="_blank">' + videoYTIdTitle[ayPos] + '\n\t\t</a>\n';
			tmpHTML  += '\t</div>\n';
		} else {
			tmpHTML  += '\t<a class="Navi" href="' + urlYTCookie + '/' + urlYTDirEmbed + '/' + videoYTId[ytPos] + '?' + videoYTParam + '" data-script="yes" alt="play">&#9658;\n\t\t</a>\n';
			tmpHTML  += '\t<div class="Title">\n';
			tmpHTML  += '\t\t<a href="' + urlYTCookie + '/' + urlYTDirEmbed + '/' + videoYTId[ytPos - 1] + '?' + videoYTParam + '" target="_blank">' + videoYTIdTitle[ayPos] + '\n\t\t</a>\n';
			tmpHTML  += '\t</div>\n';
		};
		tmpHTML  += '</div>\n';
		objSlideshow[0].innerHTML += tmpHTML;
		ayPos = ayPos + 1;
	}
	tmpHTML2 = '';
	tmpHTML2 += '\t<div class="dotContainer" style="text-align:center">\n';
	tmpHTML2 += '\t\t<div class="dotBackground">\n';
	for (let y of videoYTIdTmp) {
		tmpHTML2 += "\t\t\t<a class='dot' href='#Pos" + axPos + "' alt='" + videoYTIdTitle[axPos - 1].replace('\<cite\>','').replace('\<\/cite\>','') + "'></a>";
		axPos = axPos + 1;
	}
	tmpHTML2 += '\t\t</div>\n';
	tmpHTML2 += '\t</div>\n';
	tmpHTML2 += '\t<div class="PlayerOverlay"></div>\n';
	tmpHTML2 += '\t<div class="channelLogo"></div>\n';
	objContainerSlider[0].innerHTML += tmpHTML2;

}

async function fnMakeSlideshow_old_ok() {
	var ayPos = 0;
	var axPos = 1;
	objSlideshow[0].innerHTML = '';
	for (let x of videoYTIdTmp) {

		var ytPos = ayPos + 1;
		let tmpHTML = '<div class="SlideshowContent">\n';
		tmpHTML  += '\t<div id="Pos' + ytPos + '" class="Slide">\n';
		tmpHTML  += '\t</div>\n';
		if (x.indexOf('?') != '-1') {
			tmpHTML  += '\t<a class="Navi" href="' + urlYTCookie + '/' + urlYTDirEmbed + '/' + videoYTId[ytPos] + '' + x + '&' + videoYTParam + '" style="visibility: hidden" data-script="yes" alt="play">&#9658;\n\t\t</a>\n';
			tmpHTML  += '\t<div class="Title">\n';
			tmpHTML  += '\t\t<a href="' + urlYTCookie + '/' + urlYTDirEmbed + '/' + videoYTId[ytPos] + '' + x + '&' + videoYTParam + '" target="_blank">' + videoYTIdTitle[ayPos] + '\n\t\t</a>\n';
			tmpHTML  += '\t</div>\n';
		} else {
			tmpHTML  += '\t<a class="Navi" href="' + urlYTCookie + '/' + urlYTDirEmbed + '/' + videoYTId[ytPos] + '?' + videoYTParam + '" style="visibility: hidden" data-script="yes" alt="play">&#9658;\n\t\t</a>\n';
			tmpHTML  += '\t<div class="Title">\n';
			tmpHTML  += '\t\t<a href="' + urlYTCookie + '/' + urlYTDirEmbed + '/' + videoYTId[ytPos] + '?' + videoYTParam + '" target="_blank">' + videoYTIdTitle[ayPos] + '\n\t\t</a>\n';
			tmpHTML  += '\t</div>\n';
		};
		tmpHTML  += '</div>\n';
		objSlideshow[0].innerHTML += tmpHTML;
		ayPos = ayPos + 1;
	}
	let tmpHTML = '<div class="dotContainer" style="text-align:center">\n';
	tmpHTML += '\t<div class="dotBackground">\n';
	for (let y of videoYTIdTmp) {
		tmpHTML += "\t\t<a class='dot' href='#Pos" + axPos + "' alt='" + videoYTIdTitle[axPos - 1].replace('\<cite\>','').replace('\<\/cite\>','') + "'></a>";
		axPos = axPos + 1;
	}
	tmpHTML += '\t</div>\n';
	tmpHTML += '</div>\n';
	tmpHTML += '<div class="PlayerOverlay"></div>\n';
	tmpHTML  += '<div class="channelLogo"></div>\n';
	objContainerSlider[0].innerHTML += tmpHTML;
}


async function fnInsertYT() {
	objCreateScript.src = urlYT + "/" + apiYT;
	objFirstScriptTag.parentNode.insertBefore(objCreateScript, objFirstScriptTag);
}


async function fnMakeDot() {
		var maxPos;
		var acPos = 1;
		var strPicPos = objSlideshow[0].style.left;
		strPicPos = strPicPos.replace("vw", "");
		var picPos = strPicPos.replace("-", "");
		var nextPos;
		picPos = picPos / 100;
		maxPos = objSlide.length
		maxPos = (maxPos + 1) * 100;
		maxPos = maxPos + "vw";
		objBackDot[0].style.visibility = 'var(--show)';
		objBackDot[0].innerHTML = "";
		for (let x of videoYTIdTmp) {
			objBackDot[0].innerHTML += "<a class='dot' href='#Pos" + acPos + "'></a>";
			/*objTitle[acPos].style.visibility = 'hidden';*/
			acPos = acPos + 1;
		}
		
}

function fnReadObjStyle(cssVar, objTemp) {
		var tmpVar = cssVar;
		var tmpString ="";
		var tmpUnit ="";
		var tmpNumber = [];
		var tmpCalc = 0;
		var tmpFactor = 0;
		var tmpInt = 0;

		tmpString = getComputedStyle(objTemp).getPropertyValue(cssVar);
		tmpInt = parseInt(tmpString);
		return tmpInt;
}

function fnReadCSSVar(cssVar, objTemp) {
		var tmpVar = cssVar;
		var tmpString ="";
		var tmpUnit ="";
		var tmpNumber = [];
		var tmpCalc = 0;
		var tmpFactor = 0;
		var tmpInt = 0;

		tmpString = getComputedStyle(objTemp).getPropertyValue(cssVar);
		return tmpString;
}

function fnReRootCSS(cssVar) {
	fnReadRootCSS(cssVar);
}

function fnReadRootCSS(cssVar) {
		var tmpVar = cssVar;
		var tmpString ="";
		var tmpString2 ="";
		var tmpString3 = "";
		var tmpUnit ="";
		var tmpUnitPx = -1;
		var tmpNumber;
		var tmpCalc = 0;
		var tmpFactor = 0;
		var tmpInt = 0;
		var tmpOut = 0.00;
		var strOut;
		var startStr = 0;
		var endStr = 0;
		runcount = runcount + 1;
		tmpString = fnReadCSSVar(cssVar, root).trim();	
	
		if (tmpString.indexOf('var') >= 0) {
			startStr = tmpString.indexOf('var') + 4;
			endStr = tmpString.indexOf(')');
			tmpString2 = tmpString.substring(startStr,endStr);
			tmpString3 = fnReRootCSS(tmpString2);
			tmpString = tmpString.replace('var(' + tmpString2 + ')', tmpString3);			
		}

		if (tmpString.indexOf('em') >= 0) {
			tmpString = tmpString.replace('em','');
			tmpUnit ='em';
			tmpUnitPx = parseFloat(fontSizeEm,10);
			
		}
		if (tmpString.indexOf('px') >= 0) {
			tmpString = tmpString.replace('px','');
			tmpUnit ='px';
			tmpUnitPx = 1;
		}
		if (tmpString.indexOf('vw') >= 0) {
			tmpString = tmpString.replace('vw','');
			tmpUnit ='vw';
			tmpUnitPx = parseFloat(screenWvwPix,10);
		}
		if (tmpString.indexOf('vh') >= 0) {
			tmpString = tmpString.replace('vh','');
			tmpUnit ='vh';
			tmpUnitPx = parseFloat(screenHvwPix,10);
		}
		if (tmpString.indexOf('pt') >= 0) {
			tmpString = tmpString.replace('pt','');
			tmpUnit ='pt';
			tmpUnitPx = 1;
		}
		
		if (tmpString.indexOf('calc') >= 0) {
			tmpString = tmpString.replace('calc(','').replace(')','');
		}
		tmpString = tmpString.trim();
		
		if (tmpString.indexOf('rgb') >= 0 || tmpString.indexOf('hsl') >= 0 || tmpString.indexOf('#') >= 0) {
			tmpOut = tmpString;
		} else if (tmpString.indexOf('*') >= 0) {
			tmpNumber = tmpString.split('*');
			tmpOut =  parseFloat(tmpNumber[0],10) * parseFloat(tmpNumber[1],10) * parseFloat(tmpUnitPx,10);
		} else if (tmpString.indexOf('/') >= 0) {
			tmpNumber = tmpString.split('/');
			tmpOut =  parseFloat(tmpNumber[0],10) / parseFloat(tmpNumber[1],10) * parseFloat(tmpUnitPx,10);
		} else if (tmpString.indexOf('-') >= 0) {
			tmpNumber = tmpString.split('-');
			tmpOut =  parseFloat(tmpNumber[0],10) - parseFloat(tmpNumber[1],10) * parseFloat(tmpUnitPx,10);
		} else if (tmpString.indexOf('+') >= 0) {
			tmpNumber = tmpString.split('+');
			tmpOut =  parseFloat(tmpNumber[0],10) + parseFloat(tmpNumber[1],10) * parseFloat(tmpUnitPx,10);
		} else if (tmpString.indexOf(' ') >= 0) {
			tmpNumber = tmpString.split(' ');
			tmpOut =  parseFloat(tmpNumber[0],10) * parseFloat(tmpUnitPx,10) + ' ' + parseFloat(tmpNumber[1],10);
		} else if (parseFloat(tmpUnitPx,10) > 0 ) {
			tmpOut =  parseFloat(tmpString,10) * parseFloat(tmpUnitPx,10);
		} else {
			tmpOut = tmpString;
		}
			
		strOut = tmpOut;
			
		if (tmpOut == "NaN") {
			strOut = tmpString;
			alert(typeof strOut + '\n' + typeof tmpString);

		}
			
		return strOut;
	}

function fnWriteRootCSS(cssVar, cssValue) {
	objHTML.style.setProperty(cssVar,cssValue);
}


async function fnPlayHidden() {
		/*
		var strPicPos = objSlideshow[0].style.left;
		strPicPos = strPicPos.replace("vw", "");
		var picPos = strPicPos.replace("-", "");
		picPos = picPos / 100;
		clearInterval(runSlideshow);
		clearInterval(runFade);
		document.body.scrollTop = overlayPosTop[2];
		objHTML.scrollTop = overlayPosTop[2];
		objTitle[picPos].style.setProperty("visibility", "hidden");
		objContainerTitle[0].style.setProperty("width","var(--logoWidth)");
		objContainerTitle[0].style.setProperty("box-shadow", "var(--menuShadow)");
		*/
}

async function fnPlayShow() {
		/*
		var strPicPos = objSlideshow[0].style.left;
		strPicPos = strPicPos.replace("vw", "");
		var picPos = strPicPos.replace("-", "");
		picPos = picPos / 100;
		if (videoPlay != 1) {
			objTitle[picPos].style.removeProperty("visibility", "hidden");
			objTitle[picPos].style.removeProperty("visibility", "hidden");
			objContainerTitle[0].style.removeProperty("width","var(--logoWidth)");
			objContainerTitle[0].style.removeProperty("box-shadow", "var(--menuShadow)");
		}
		*/
}


async function fnStartInterval() {
  		/*
		if (!timer_on && videoPlay != 1 ) {
    			timer_on = 1;
			activeScroll = 0;
    			fnPlayShow();*/
			/*runFade = setInterval(fnFadeText, 5000);
			objBackDot[0].style.visibility = 'var(--show)';*/
			/*if (screen.height < 1024) {
				objHeader[0].style.visibility = 'var(--show)';
			}
		}
		*/
}

async function fnStopInterval() {
		/*
		timer_on = 0;
		activeScroll = 1;
		clearInterval(runSlideshow);
		clearInterval(runFade);
		fnPlayHidden(); */
		/*objBackDot[0].style.visibility = 'hidden';*/
		/*
		if (screen.height < 1024) {
			objHeader[0].style.visibility = 'hidden';
		}
		*/
}


async function fnAnimateSubPic(xBackGrPic, Action) {
	/*
	var action = Action;
	if (action === "visible") {
		for (let xPic = 0, len = objBackGImg.length; xPic < len; xPic++) {
			objBackGImg[xPic].style.opacity = 'var(--noTransparent)';
			objBackGImg[xPic].style.overflowY = 'var(--overflowVisible)';
		};
		objScrollPic[xBackGrPic].style.perspective = 'var(--animiStartPerspective)';
		objScrollPic[xBackGrPic].style.setProperty("-webkit-perspective","var(--animiStartPerspective)", "important");
		objScrollPic[xBackGrPic].style.setProperty("-moz-perspective","var(--animiStartPerspective)", "important");
		objScrollPic[xBackGrPic].style.overflowY = 'var(--overflowVisible)';
		
	} else if (action === "animate" || action === "animated") {
		for (let xPic = 0, len = objBackGImg.length; xPic < len; xPic++) {
			objBackGImg[xPic].style.opacity = 'var(--noTransparent)';
			objBackGImg[xPic].style.overflowY = 'var(--overflowVisible)';
		};
		objScrollPic[xBackGrPic].style.perspective = 'var(--animiStopPerspective)';
		objScrollPic[xBackGrPic].style.setProperty("-webkit-perspective","var(--animiStopPerspective)", "important");
		objScrollPic[xBackGrPic].style.setProperty("-moz-perspective","var(--animiStopPerspective)", "important");
		objScrollPic[xBackGrPic].style.overflowY = 'var(--overflowVisible)';
		
	} else if (action === "hidden") {
		for (let xPic = 0, len = objBackGImg.length; xPic < len; xPic++) {
			objBackGImg[xPic].style.opacity = 'var(--transparent)';
			objBackGImg[xPic].style.overflowY = 'var(--overflowCut)';
		};
		objScrollPic[xBackGrPic].style.perspective = 'var(--animiStartPerspective)';
		objScrollPic[xBackGrPic].style.setProperty("-webkit-perspective","var(--animiStartPerspective)", "important");
		objScrollPic[xBackGrPic].style.setProperty("-moz-perspective","var(--animiStartPerspective)", "important");
		objScrollPic[xBackGrPic].style.overflowY = 'var(--overflowHidden)';
		
	} else {
		alert('Wrong Action-Parameter\n'+ action );
	};
	*/
}

function fnOnScroll() {
	let winScrollY = Math.round(window.scrollY);

	if (lastScrollY != winScrollY ) {
		lastScrollY = winScrollY;
		fnRequestTick();
	}
}

function fnRequestTick() {
	if(!ticking) {
		requestAnimationFrame(fnScrollObject);
		ticking = true;
	}
}


async function fnScrollObject() {

		screenHeight = window.innerHeight;
		objMain = document.getElementById("main");
		objPos = document.getElementById("NaviDown");
		fnWriteRootCSS("--scrollPos",lastScrollY);
		var scrollPos = lastScrollY;		
		scrollPosScreenTop = lastScrollY;
		scrollPosHeaderBottom = scrollPosScreenTop + headerHeight + fontSizeEm;
		scrollPosFooterTop = scrollPosScreenTop + screenHeight - footerHeight;
		scrollPosScreenBottom =scrollPosScreenTop + screenHeight;
		
		if (screenHProcent < screenWProcent) {
			screenProcent = screenHProcent;
		} else {
			screenProcent = screenWProcent;
		}
		videoHeight = Math.round(screenProcent * factorHDVideo);
		videoMinHeight = Math.round(screenProcent * factorLetterBoxVideo);
		withoutVideoHeight = documentHeight - videoHeight;
		ticking = false;

}


async function fnSetOnLoad() {
		var ayPos = 0;
		fnChkBrowserVersion();
		documentHeight = objHTML.style.height;
		objMain = document.getElementById("main");
		objPos = document.getElementById("NaviDown");
		objScrollPic = document.getElementsByClassName("scrollPic");
		objBibleText = document.getElementsByClassName("bibleText");
		objSlideshow = document.getElementsByClassName("Slideshow");
		fnMakeSlideshow();
		fnInsertYT();
		objSlideshow = document.getElementsByClassName("Slideshow");
		objMainSlideshow = document.getElementById("mainSlideshow");
		objContainerSlideshow = document.getElementsByClassName("containerSlideshow");
		objContainerSlider = document.getElementsByClassName("containerSlider");
		objContDot = document.getElementsByClassName("dotContainer");
		objBackDot = document.getElementsByClassName("dotBackground");
		objDot = document.getElementsByClassName("dot");
		objHeader = document.getElementsByClassName("header");
		objNavi = document.getElementsByClassName("Navi");
		objTitle = document.getElementsByClassName("Title");
		objContainerTitle = document.getElementsByClassName("PlayerOverlay");
		objSlide = document.getElementsByClassName("Slide");
		document.body.scrollTop = 0;
		objHTML.scrollTop = 0;
		
		/* no State on load  --> Activate Livestream on Pos9 */  
		objSlide[9].style.setProperty("content-visibility","var(--show)", "");
		
}

function onYouTubeIframeAPIReady() {

		for (let xYT = 0, len = videoYTIdTmp.length; xYT< len; xYT++) {
			let yYT = xYT + 1;
			let videoID = videoYTIdTmp[xYT].replace('videoseries','');
					
			if (videoYTIdTmp[xYT].search("user_uploads") >= 0) {
				playerTmp[xYT] = new YT.Player('Pos' + yYT + '', {
					wmode: 'transparent',
					host: '' + urlYTCookie + '',
					height: '' + videoHeigth + '',
					width: '' + videoWidth + '',
					allow: '' + apiYTPermission + '',
					title: '' + videoYTIdTitle[xYT].replace('\<cite\>','').replace('\<\/cite\>','').replace('\<a\>','').replace('<\</a\>','') ,
					playerVars: {
						list: '' + videoYTIdTmp[xYT].replace('\&listType\=user\_uploads','').replace('\?list\=',''),
						listType: 'user_uploads',
						no_cookie: '1',
						modestbranding: '0',
						origin: '' + originComplite + '',
						showinfo: '0',
						autoplay: '0',
						rel: '0',
						controls: '0',
						enablejsapi: '1',
						fs: '0',
						disablekb: '1',
						clipboard_write: '0',
						iv_load_poliy: '3',
						cc_load_poliy: '0',
						encrypted_media: '1',
						wmode: 'transparent',
						title: '0',
						playsinline: '1',
						setPlaybackRate: 'hd1080' 
					},
					events: {
						'onReady': fnOnYTPlayerReady,
						'onError': fnOnYTPlayerError,
						'onStateChange': fnOnYTPlayerStateChange
					}
        			});

			} else if (videoYTIdTmp[xYT].search("PL") >= 0 || videoYTIdTmp[xYT].search("list\=") >= 0 ) {
				playerTmp[xYT] = new YT.Player('Pos' + yYT + '', {
					wmode: 'transparent',
					host: '' + urlYTCookie + '',
					height: '' + videoHeigth + '',
					width: '' + videoWidth + '',
					allow: '' + apiYTPermission + '',
					title: '' + videoYTIdTitle[xYT].replace('\<cite\>','').replace('\<\/cite\>','').replace('\<a\>','').replace('<\</a\>','') ,
					playerVars: {
						list: '' + videoYTIdTmp[xYT].replace('\?list\=',''),
						no_cookie: '1',
						modestbranding: '0',
						origin: '' + originComplite + '',
						showinfo: '0',
						autoplay: '0',
						rel: '0',
						controls: '0',
						enablejsapi: '1',
						fs: '0',
						disablekb: '1',
						clipboard_write: '0',
						iv_load_poliy: '3',
						cc_load_poliy: '0',
						encrypted_media: '1',
						wmode: 'transparent',
						title: '0',
						playsinline: '1',
						setPlaybackRate: 'hd1080' 
					},
					events: {
						'onReady': fnOnYTPlayerReady,
						'onError': fnOnYTPlayerError,
						'onStateChange': fnOnYTPlayerStateChange
					}
        			});
			} else {

				playerTmp[xYT] = new YT.Player('Pos' + yYT + '', {
					wmode: 'transparent',
					host: '' + urlYTCookie + '',
					height: '' + videoHeigth + '',
					width: '' + videoWidth + '',
					allow: '' + apiYTPermission + '',
					title: '' + videoYTIdTitle[xYT].replace('\<cite\>','').replace('\<\/cite\>','').replace('\<a\>','').replace('<\</a\>','') ,
					videoId: '' + videoYTIdTmp[xYT] + '',
					playerVars: {
						no_cookie: '1',
						modestbranding: '0',
						origin: '' + originComplite + '',
						showinfo: '0',
						autoplay: '0',
						rel: '0',
						controls: '0',
						enablejsapi: '1',
						fs: '0',
						disablekb: '1',
						clipboard_write: '0',
						iv_load_poliy: '3',
						cc_load_poliy: '0',
						encrypted_media: '1',
						wmode: 'transparent',
						title: '0',
						playsinline: '1',
						setPlaybackRate: 'hd1080' 
					},
					events: {
						'onReady': fnOnYTPlayerReady,
						'onError': fnOnYTPlayerError,
						'onStateChange': fnOnYTPlayerStateChange
					}
        			});
			}
		}
	}


function fnOnYTPlayerReady(event) {
		var indexSlide = event.target.id - 1;
		/*alert(indexSlide + '\n' + event.target.id + '\n' + objSlide[indexSlide].title );*/
		objSlideshow[0].style.opacity = 'var(--noTransparent)';
		objSlide[1].style.setProperty("content-visibility","var(--show)");
		/*objSlide[indexSlide].style.setProperty("content-visibility","var(--show)","important");
		objNavi[indexSlide].style.setProperty("display","var(--unshow)","important");
		alert(objSlide[indexSlide].getAttribute("src"));
		var ifTitle = objSlide[indexSlide].contentWindow.document.getElementsByClassName("ytp-show-cards-title");
		ifTitle[0].style.setPorperty("display","none");*/
		objNavi[indexSlide].style.removeProperty("visibility","hidden","");
		objNavi[indexSlide].removeAttribute("href");
		objNavi[indexSlide].setAttribute("onClick","callPlayer('playVideo',''," + indexSlide + " )");
		objNavi[indexSlide].style.setProperty("backgroundBlendMode","normal");
	}

function fnOnYTPlayerStateChange(event) {
		var indexSlide = event.target.id - 1;
		switch (event.data) {
			case -1:
				//alert(' not started');
				objSlideshow[0].style.opacity = 1;
				objTitle[indexSlide].style.visibility = 'var(--show)';
				objContainerTitle[0].style.setProperty("visibility","var(--show)");
				objHeader[0].style.setProperty("visibility","var(--show)");
				objSlide[indexSlide].style.setProperty("content-visibility","var(--unshow)", "");
				objNavi[indexSlide].style.setProperty("display","var(--show)");
				objContDot[0].style.setProperty("display","var(--show)");
				objPreview[indexSlide].style.removeProperty("display","var(--hidden)");
				videoPlay = 0;
				break;
			case 0:
				//alert(' ended');
				objSlideshow[0].style.opacity = 1;
				objTitle[indexSlide].style.visibility = 'var(--show)';
				fnOnYTPlayerStateStop(event.target.id);
				objContainerTitle[0].style.setProperty("visibility","var(--show)");
				objHeader[0].style.setProperty("visibility","var(--show)");
				objSlide[indexSlide].style.setProperty("content-visibility","var(--unshow)", "");
				objNavi[indexSlide].style.setProperty("display","var(--show)");
				objContDot[0].style.setProperty("display","var(--show)");
				objPreview[indexSlide].style.removeProperty("display","var(--hidden)");
				videoPlay = 0;
				break;
			case 1:
				//alert(' play');
				objSlideshow[0].style.opacity = 1;
				objTitle[indexSlide].style.visibility = 'var(--unshow)';
				objContainerTitle[0].style.setProperty("visibility","var(--unshow)");
				objHeader[0].style.setProperty("visibility","var(--unshow)");
				objSlide[indexSlide].style.setProperty("content-visibility","var(--show)", "important");
				objNavi[indexSlide].style.setProperty("display","var(--hidden)");
				objContDot[0].style.setProperty("display","var(--hidden)");
				objPreview[indexSlide].style.setProperty("display","var(--hidden)");
				videoPlay = 1;
				fnOnYTPlayerStatePlay(event.target.id);
				break;
			case 2:
				//alert(' paused');
				objSlideshow[0].style.opacity = 1;
				objTitle[indexSlide].style.visibility = 'var(--show)';
				objContainerTitle[0].style.setProperty("visibility","var(--show)");
				objHeader[0].style.setProperty("visibility","var(--show)");
				objSlide[indexSlide].style.setProperty("content-visibility","var(--unshow)", "");
				objNavi[indexSlide].style.setProperty("display","var(--show)");
				objContDot[0].style.setProperty("display","var(--show)");
				objPreview[indexSlide].style.removeProperty("display","var(--hidden)");
				videoPlay = 0;
				fnOnYTPlayerStatePause(event.target.id);
				break;
			case 3:
				//alert(' buffering');
				videoPlay = 1;
				objSlideshow[0].style.opacity = 'var(--halfTransparent)';
				objContainerTitle[0].style.setProperty("visibility","var(--unshow)");
				objHeader[0].style.setProperty("visibility","var(--unshow)");
				objSlide[indexSlide].style.setProperty("content-visibility","var(--show)", "");
				objNavi[indexSlide].style.setProperty("display","var(--show)");
				objContDot[0].style.setProperty("display","var(--show)");
				objPreview[indexSlide].style.removeProperty("display","var(--hidden)");
				break;
			case 4:
				//alert(' 4');
				break;

			case 5:
				//alert(' cued');
				videoPlay = 1;
				objTitle[indexSlide].style.visibility = 'var(--show)';
				objContainerTitle[0].style.setProperty("visibility","var(--show)");
				objHeader[0].style.setProperty("visibility","var(--show)");
				objSlide[indexSlide].style.setProperty("content-visibility","var(--show)", "");
				objNavi[indexSlide].style.setProperty("display","var(--show)");
				objContDot[0].style.setProperty("display","var(--show)");
				objSlideshow[0].style.opacity = 1;
				objPreview[indexSlide].style.removeProperty("display","var(--hidden)");
				break;
		}
	}



function fnOnYTPlayerError(event) {
		var indexSlide = event.target.id - 1;
		objSlideshow[0].style.opacity = 1;
		objTitle[indexSlide].style.visibility = 'var(--show)';
		objContainerTitle[0].style.setProperty("visibility","var(--show)");
		objHeader[0].style.setProperty("visibility","var(--show)");
		objSlide[indexSlide].style.setProperty("content-visibility","var(--unshow)", "");
		objNavi[indexSlide].style.setProperty("display","var(--show)");
		objContDot[0].style.setProperty("display","var(--show)");
		objPreview[indexSlide].style.removeProperty("display","var(--hidden)");
		switch (event.data) {
			case 2:   
				/*false Parameter*/
				objInfoTXT[3].innerHTML = event.target.id + ': ' + event.data + ' false Parameter';
				break;
			case 5:
				/*no HTML5 Player*/
				objInfoTXT[3].innerHTML = event.target.id + ': ' + event.data + ' no HTML5';
				break;
			case 100:
				/*video not found*/
				objInfoTXT[3].innerHTML = event.target.id + ': ' + event.data + ' Video(s) not found';
				break;
			case 101:
				/*no Privelege*/
				objInfoTXT[3].innerHTML = event.target.id + ': ' + event.data + ' no Access';
				break;
			case 150:
				/*no Privelege*/
				objInfoTXT[3].innerHTML = event.target.id + ': ' + event.data + 'no Access';
				break;
		} 
	}



function fnOnYTPlayerStatePlay(inID) {	
			/*alert('PlayState ' + inID); */
			timer_on = 0;
			activeScroll = 1;
			videoPlay = 1;
			YTdone = true;
	}

function fnOnYTPlayerStateStop(inID) {
			/*alert('StopState ' + inID); */
			timer_on = 1;
			activeScroll = 0;
			videoPlay = 0;
			YTdone = false;
	}

function fnOnYTPlayerStatePause(inID) {	
			/*alert('PauseState ' + inID); */
			YTdone = true;
	}


function fnStopYTVideo() {
		player.stopVideo();
		YTdone = false;
}


async function fnBackBook() { 
		var objLastPage = document.getElementsByClassName("left");
		var objContentLast = document.getElementsByClassName("BookContent");
		objLastPage[0].style.transition = 'var(--transitionLong)';
		objLastPage[0].style.transform = 'rotateY(180deg)';
		await fnSleep(125);
		objContentLast[1].style.visibility = 'hidden';
		await fnSleep(375);
		objContentLast[1].style.visibility = 'var(--show)';
		objLastPage[0].style.transition = 'var(--transitionNone)';
		objLastPage[0].style.transform = 'rotateY(0deg)';

}

async function fnNextBook() { 
		var objNextPage = document.getElementsByClassName("right");
		var objContentNext = document.getElementsByClassName("BookContent");
		objNextPage[0].style.transition = 'var(--transition)';
		objNextPage[0].style.transform = 'rotateY(180deg)';
		await fnSleep(125); /*63*/
		objContentNext[3].style.visibility = 'hidden';
		await fnSleep(375); /*187*/
		objContentNext[3].style.visibility = 'var(--show)';
		objNextPage[0].style.transition = 'var(--transitionNone)';
		objNextPage[0].style.transform = 'rotateY(0deg)';
}

/*alert('no Syntax Error');*/
