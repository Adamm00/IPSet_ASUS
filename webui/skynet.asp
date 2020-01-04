<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<html xmlns:v>
<head>
<meta http-equiv="X-UA-Compatible" content="IE=Edge"/>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta HTTP-EQUIV="Pragma" CONTENT="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="-1">
<link rel="shortcut icon" href="images/favicon.png">
<link rel="icon" href="images/favicon.png">
<title>Skynet Statistics</title>
<link rel="stylesheet" type="text/css" href="index_style.css">
<link rel="stylesheet" type="text/css" href="form_style.css">
<style>
p{
font-weight: bolder;
}

thead.collapsible {
  color: white;
  padding: 0px;
  width: 100%;
  border: none;
  text-align: left;
  outline: none;
  cursor: pointer;
}

thead.collapsibleparent {
  color: white;
  padding: 0px;
  width: 100%;
  border: none;
  text-align: left;
  outline: none;
  cursor: pointer;
}

td.keystatsnumber {
  font-size: 20px !important;
  font-weight: bolder !important;
}

td.nodata {
  font-size: 48px !important;
  font-weight: bolder !important;
  height: 65px !important;
  font-family: Arial !important;
}

.StatsTable {
  table-layout: fixed !important;
  width: 747px !important;
  text-align: center !important;
}

.StatsTable th {
  background-color:#1F2D35 !important;
  background:#2F3A3E !important;
  border-bottom:none !important;
  border-top:none !important;
  font-size: 12px !important;
  color: white !important;
  padding: 4px !important;
  width: 740px !important;
}

.StatsTable td {
  padding: 2px !important;
  word-wrap: break-word !important;
  overflow-wrap: break-word !important;
}

.StatsTable a {
  font-weight: bolder !important;
  text-decoration: underline !important;
}

.StatsTable th:first-child,
.StatsTable td:first-child {
  border-left: none !important;
}

.StatsTable th:last-child ,
.StatsTable td:last-child {
  border-right: none !important;
}

</style>
<script language="JavaScript" type="text/javascript" src="/js/jquery.js"></script>
<script language="JavaScript" type="text/javascript" src="/js/chart.min.js"></script>
<script language="JavaScript" type="text/javascript" src="/ext/skynet/hammerjs.js"></script>
<script language="JavaScript" type="text/javascript" src="/ext/skynet/chartjs-plugin-zoom.js"></script>
<script language="JavaScript" type="text/javascript" src="/state.js"></script>
<script language="JavaScript" type="text/javascript" src="/general.js"></script>
<script language="JavaScript" type="text/javascript" src="/popup.js"></script>
<script language="JavaScript" type="text/javascript" src="/help.js"></script>
<script language="JavaScript" type="text/javascript" src="/tmhist.js"></script>
<script language="JavaScript" type="text/javascript" src="/tmmenu.js"></script>
<script language="JavaScript" type="text/javascript" src="/client_function.js"></script>
<script language="JavaScript" type="text/javascript" src="/validator.js"></script>
<script language="JavaScript" type="text/javascript" src="/ext/skynet/stats.js"></script>

<script>
var ChartInPortHits;
Chart.defaults.global.defaultFontColor = "#CCC";
Chart.Tooltip.positioners.cursor = function(chartElements, coordinates) {
	return coordinates;
};

function Draw_Chart_NoData(txtchartname){
	document.getElementById("divChart"+txtchartname).width="735";
	document.getElementById("divChart"+txtchartname).height="360";
	document.getElementById("divChart"+txtchartname).style.width="735px";
	document.getElementById("divChart"+txtchartname).style.height="360px";
	var ctx = document.getElementById("divChart"+txtchartname).getContext("2d");
	ctx.save();
	ctx.textAlign = 'center';
	ctx.textBaseline = 'middle';
	ctx.font = "normal normal bolder 48px Arial";
	ctx.fillStyle = 'white'
	ctx.fillText('No data to display', 368, 180);
	ctx.restore();
}

function Draw_Chart(txtchartname,multilabel){
	var objchartname=window["Chart"+txtchartname];
	var objdataname=GetDataDataset(txtchartname,multilabel);
	var objlabeldataname;
	var charttype=getChartType($("#"+txtchartname+"_Type option:selected").val());
	var chartcolour=getChartColour($("#"+txtchartname+"_Colour option:selected").val());
	if(typeof objdataname === 'undefined' || objdataname === null){ Draw_Chart_NoData(txtchartname); return;}
	if(objdataname.length == 0) {Draw_Chart_NoData(txtchartname); return;}

	if(multilabel=="true"){
		objlabeldataname_IPs=window["Label"+txtchartname+"_IPs"];
		objlabeldataname_Sorted=window["Label"+txtchartname+"_Sorted"];
		if(typeof objlabeldataname_IPs === 'undefined' || objlabeldataname_IPs === null) {Draw_Chart_NoData(txtchartname); return;}
		if(objlabeldataname_IPs.length == 0) {Draw_Chart_NoData(txtchartname); return;}
		if(typeof objlabeldataname_Sorted === 'undefined' || objlabeldataname_Sorted === null) {Draw_Chart_NoData(txtchartname); return;}
		if(objlabeldataname_Sorted.length == 0) {Draw_Chart_NoData(txtchartname); return;}
	} else {
		objlabeldataname=window["Label"+txtchartname];
		if(typeof objlabeldataname === 'undefined' || objlabeldataname === null) {Draw_Chart_NoData(txtchartname); return;}
		if(objlabeldataname.length == 0) {Draw_Chart_NoData(txtchartname); return;}
	}

	if (objchartname != undefined) objchartname.destroy();
	var ctx = document.getElementById("divChart"+txtchartname).getContext("2d");
	var chartOptions = {
		segmentShowStroke : false,
		segmentStrokeColor : "#000",
		animationEasing : "easeOutQuart",
		animationSteps : 100,
		maintainAspectRatio: false,
		animateScale : true,
		legend: { display: false, position: "bottom", onClick: null },
		title: {
			display: showTitle(charttype),
			text: getChartLegendTitle(charttype,txtchartname),
			position: "top"
		},
		tooltips: {
			callbacks: {
				title: function (tooltipItem, data) { return data.labels[tooltipItem[0].index]; },
				label: function (tooltipItem, data) { return comma(data.datasets[tooltipItem.datasetIndex].data[tooltipItem.index]); },
			},
			mode: 'point',
			position: 'cursor',
			intersect: true
		},
		scales: {
			xAxes: [{
				display: showAxis(charttype,"x"),
				gridLines: { display: showGrid(charttype,"x"), color: "#282828" },
				scaleLabel: { display: true, labelString: getAxisLabel(charttype,"x",txtchartname) },
				ticks: { display: showTicks(charttype,"x"), beginAtZero: false }
			}],
			yAxes: [{
				display: showAxis(charttype,"y"),
				gridLines: { display: false, color: "#282828" },
				scaleLabel: { display: true, labelString: getAxisLabel(charttype,"y",txtchartname) },
				ticks: { display: showTicks(charttype,"y"), beginAtZero: false }
			}]
		},
		legend: {
			display: showLegend(charttype),
			position: "left",
			labels: {
				fontColor: "#ffffff"
			}
		},
		plugins: {
			zoom: {
				pan: {
					enabled: true,
					mode: ZoomPanEnabled(charttype),
					rangeMin: {
						x: 0,
						y: 0
					},
					rangeMax: {
						x: ZoomPanMax(charttype,"x",objdataname),
						y: ZoomPanMax(charttype,"y",objdataname)
					},
				},
				zoom: {
					enabled: true,
					mode: ZoomPanEnabled(charttype),
					rangeMin: {
						x: 0,
						y: 0
					},
					rangeMax: {
						x: ZoomPanMax(charttype,"x",objdataname),
						y: ZoomPanMax(charttype,"y",objdataname)
					},
					speed: 0.1,
				}
			}
		}
	};
	var chartDataset = {
		labels: GetLabelDataset(txtchartname,multilabel),
		datasets: [{data: objdataname,
			borderWidth: 1,
			backgroundColor: poolColors(objdataname.length),
			borderColor: "#000000",
		}]
	};
	objchartname = new Chart(ctx, {
		type: charttype,
		options: chartOptions,
		data: chartDataset
	});
	window["Chart"+txtchartname]=objchartname;
}

function GetDropdownCookie(cookiename) {
	var s;
	if ((s = cookie.get(cookiename)) != null) {
			if (s.match(/^([0-2])$/)) {
				$("#"+cookiename).val(cookie.get(cookiename) * 1);
			}
	}
}

function GetExpandedCookie(cookiename) {
	var s;
	if ((s = cookie.get(cookiename)) != null) {
		return cookie.get(cookiename);
	}
	else {
		return ""
	}
}

function SetCookie(cookiename,cookievalue) {
	cookie.set(cookiename, cookievalue, 31);
}

function SetCurrentPage(){
	$("#next_page").val(window.location.pathname.substring(1));
	$("#current_page").val(window.location.pathname.substring(1));
}

function AddEventHandlers(){
	$(".collapsible").click(function(){
		if ($(this).hasClass("expanded")) {
			$(this).removeClass("expanded").addClass("collapsed");
			SetCookie($(this).attr("id"),"collapsed");
		} else {
			$(this).removeClass("collapsed").addClass("expanded");
			SetCookie($(this).attr("id"),"expanded");
		}
		$(this).siblings().toggle("fast");
	})

	$(".default-collapsed").trigger("click");
}

function SetExpanded(){
	var coll = $(".collapsible");
	var i;

	for (i = 0; i < coll.length; i++) {
		if(GetExpandedCookie(coll[i].id) == "collapsed"){
			$("#"+coll[i].id).trigger("click");
		}
	}
}

function initial(){
	$("#skynet_table_keystats").after(BuildChartHtml("Top 10 Blocked Devices (Outbound)","TCConnHits","false"));

	$("#skynet_table_keystats").after(BuildChartHtml("Top 10 Blocks (Outbound)","TOConnHits","true"));
	$("#skynet_table_keystats").after(BuildChartHtml("Top 10 Blocks (Inbound)","TIConnHits","true"));
	$("#skynet_table_keystats").after(BuildChartHtml("Top 10 HTTP(s) Blocks (Outbound)","THConnHits","true"));

	$("#skynet_table_keystats").after(BuildTableHtml("Last 10 Unique HTTP(s) Blocks (Outbound)","HTTPConn"));
	$("#skynet_table_keystats").after(BuildTableHtml("Last 10 Unique Connections Blocked (Outbound)","OutConn"));
	$("#table_keystats").after(BuildTableHtml("Last 10 Unique Connections Blocked (Inbound)","InConn"));

	$("#skynet_table_keystats").after(BuildChartHtml("Top 10 Source Ports (Inbound)","SPortHits","false"));
	$("#skynet_table_keystats").after(BuildChartHtml("Top 10 Targeted Ports (Inbound)","InPortHits","false"));

	var charts = ["InPortHits", "SPortHits", "TCConnHits"];
	charts.forEach(ChartSetup,"false");

	var multilabelcharts = ["THConnHits", "TIConnHits", "TOConnHits"];
	multilabelcharts.forEach(ChartSetup,"true");

	AddEventHandlers();
	SetExpanded();

	SetCurrentPage();

	SetStatsDate();
	SetBLCount1();
	SetBLCount2();
	SetHits1();
	SetHits2();

	show_menu();
}

Array.prototype.getDuplicates = function () {
	var duplicates = {};
	for (var i = 0; i < this.length; i++) {
		if(duplicates.hasOwnProperty(this[i])) {
			duplicates[this[i]].push(i);
		} else if (this.lastIndexOf(this[i]) !== i) {
			duplicates[this[i]] = [i];
		} else {
			duplicates[this[i]] = [i];
		}
	}
	return duplicates;
};

function ChartSetup(item, index){
	//GetDropdownCookie(item+"_Colour");
	GetDropdownCookie(item+"_Type");
	if(this=="true") {
		GetDropdownCookie(item+"_Group");

		var GroupedArray = window["Label"+item+"_Country"].getDuplicates();
		var SummedArray = [];
		var SortedArray = [];

		for (var name in GroupedArray) {
				if(name != ""){
				var sum=0;
				var name2=eval("GroupedArray."+name);
				for (var i2 = 0; i2 < name2.length; i2++) {
					sum = sum + (window["Data"+item][name2[i2]]*1);
				}
				SummedArray.push(sum);
				SortedArray.push(name);
			}
		}

		arrayOfObj = SortedArray.map(function(d, i) {
			return {
				label: d,
				data: SummedArray[i] || 0
			};
		});

		sortedArrayOfObj = arrayOfObj.sort(function(a, b) {
			return b.data - a.data;
		});

		newSortedArray = [];
		newSummedArray = [];
		sortedArrayOfObj.forEach(function(d){
			newSortedArray.push(d.label);
			newSummedArray.push(d.data);
		});

		window["Label"+item+"_Sorted"] = newSortedArray;
		window["Data"+item+"_Sum"] = newSummedArray;
	}
	Draw_Chart(item,this);
}

function reload() {
	location.reload(true);
}

function applyRule() {
	var action_script_tmp = "start_SkynetStats";
	document.form.action_script.value = action_script_tmp;
	var restart_time = document.form.action_wait.value*1;
	parent.showLoading(restart_time, "waiting");
	document.form.submit();
}

function getSDev(datasetname){
	var avg = getAvg(datasetname);

	var squareDiffs = datasetname.map(function(value){
		var diff = value - avg;
		var sqrDiff = diff * diff;
		return sqrDiff;
	});

	var avgSquareDiff = getAvg(squareDiffs);
	var stdDev = Math.sqrt(avgSquareDiff);
	return stdDev;
}

function getMax(datasetname) {
	max = Math.max(...datasetname)
	return max + (max*0.1);
}

function getAvg(datasetname) {
	var sum, avg = 0;

	if (datasetname.length) {
		sum = datasetname.reduce(function(a, b) { return a*1 + b*1; });
		avg = sum / datasetname.length;
	}

	return avg;
}

function getRandomColor() {
	var r = Math.floor(Math.random() * 255);
	var g = Math.floor(Math.random() * 255);
	var b = Math.floor(Math.random() * 255);
	return "rgba(" + r + "," + g + "," + b + ", 1)";
}

function poolColors(a) {
	var pool = [];
	for(i = 0; i < a; i++) {
		pool.push(getRandomColor());
	}
	return pool;
}

function getChartColour(colour,length) {
	var chartcolour = "rgba(2, 53, 135, 1)";
	if ( colour == 0 ) chartcolour = poolColors(length);
	return chartcolour;
}

function getChartType(layout) {
	var charttype = "horizontalBar";
	if ( layout == 0 ) charttype = "horizontalBar";
	else if ( layout == 1 ) charttype = "bar";
	else if ( layout == 2 ) charttype = "pie";
	return charttype;
}

var charts = ["InPortHits", "SPortHits", "TCConnHits"];

var multilabelcharts = ["THConnHits", "TIConnHits", "TOConnHits"];

function getAxisLabel(type,axis,txtchartname) {
	var axislabel = "";
	var value=$("#"+txtchartname+"_Group option:selected").val();
	if(axis == "x" ){
		if ( type == "horizontalBar" ) axislabel = "Hits";
		else if ( type == "bar" ) {
			if(txtchartname.indexOf("Port") != -1){
				axislabel="Port Number"
			} else if (txtchartname == "TCConnHits") {
				axislabel = "IP Address"
			} else if ( value == 0) {
				axislabel = "IP Address"
			} else if ( value == 1) {
				axislabel = "Country Code"
			}
		} else if ( type == "pie" ) axislabel = "";
		return axislabel;
	} else if(axis == "y" ){
		if ( type == "horizontalBar" ) {
			if(txtchartname.indexOf("Port") != -1){
				axislabel="Port Number"
			} else if (txtchartname == "TCConnHits") {
				axislabel = "IP Address"
			} else if ( value == 0) {
				axislabel = "IP Address"
			} else if ( value == 1) {
				axislabel = "Country Code"
			}
		}
		else if ( type == "bar" ) axislabel = "Hits";
		else if ( type == "pie" ) axislabel = "";
		return axislabel;
	}
}

function getChartLegendTitle(type,txtchartname) {
	var chartlegendtitlelabel = "";
	var value=$("#"+txtchartname+"_Group option:selected").val();
	if(txtchartname.indexOf("Port") != -1){
		chartlegendtitlelabel="Port Number"
	} else if (txtchartname == "TCConnHits") {
		chartlegendtitlelabel = "IP Address"
	} else if ( value == 0) {
		chartlegendtitlelabel = "IP Address"
	} else if ( value == 1) {
		chartlegendtitlelabel = "Country Code"
	}

	for(i=0; i < 350-chartlegendtitlelabel.length; i++){
		chartlegendtitlelabel = chartlegendtitlelabel + " ";
	}

	return chartlegendtitlelabel;
}

function GetDataDataset(txtchartname,multilabel){
	if(multilabel=="false"){
		return window["Data"+txtchartname];
	} else {
		value=$("#"+txtchartname+"_Group option:selected").val();
		if(value==0){
			return window["Data"+txtchartname];
		} else{
			return window["Data"+txtchartname+"_Sum"];
		}
	}
}

function GetLabelDataset(txtchartname,multilabel){
	if(multilabel=="false"){
		return window["Label"+txtchartname];
	} else {
		value=$("#"+txtchartname+"_Group option:selected").val();
		if(value==0){
			return window["Label"+txtchartname+"_IPs"];
		} else{
			return window["Label"+txtchartname+"_Sorted"];
		}
	}
}

function ZoomPanEnabled(charttype) {
	if (charttype == "bar") {
		return 'y';
	}
	else if (charttype == "horizontalBar") {
		return 'x';
	}
	else {
		return '';
	}
}

function ZoomPanMax(charttype, axis, datasetname) {
	if (axis == "x") {
		if (charttype == "bar") {
			return null;
		}
		else if (charttype == "horizontalBar") {
			return getMax(datasetname);
		}
		else {
			return null;
		}
	}
	else if (axis == "y") {
		if (charttype == "bar") {
			return getMax(datasetname);
		}
		else if (charttype == "horizontalBar") {
			return null;
		}
		else {
			return null;
		}
	}
}

function showGrid(e,axis) {
	if (e == null) {
		return true;
	}
	else if (e == "pie") {
		return false;
	}
	else {
		return true;
	}
}

function showAxis(e,axis) {
	if (e == "bar" && axis == "x") {
		return true;
	}
	else {
		if (e == null) {
			return true;
		}
		else if (e == "pie") {
			return false;
		}
		else {
			return true;
		}
	}
}

function showTicks(e,axis) {
	if (e == "bar" && axis == "x") {
		return false;
	}
	else {
		if (e == null) {
			return true;
		}
		else if (e == "pie") {
			return false;
		}
		else {
			return true;
		}
	}
}

function showLegend(e) {
	if (e == "pie") {
		return true;
	} else {
		return false;
	}
}

function showTitle(e) {
	if (e == "pie") {
		return true;
	} else {
		return false;
	}
}

function changeChart(e,multilabel) {
	value = e.value * 1;
	cookie.set(e.id, value, 31);
	name=e.id.substring(0,e.id.indexOf("_"));
	Draw_Chart(name,multilabel);
}

function BuildChartHtml(txttitle,txtbase,multilabel){
	var charthtml='<div style="line-height:10px;">&nbsp;</div>';
	charthtml+='<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable">';
	charthtml+='<thead class="collapsible expanded" id="skynet_chart_'+txtbase+'"';
	charthtml+='<tr><td colspan="2">' + txttitle + ' (click to expand/collapse)</td></tr>';
	charthtml+='</thead>';
	/* Colour selector start ---
	charthtml+='<tr class="even">';
	charthtml+='<th width="40%">Style for chart</th>';
	charthtml+='<td>';
	charthtml+='<select style="width:100px" class="input_option" onchange="changeChart(this,\''+multilabel+'\')" id="' + txtbase + '_Colour">';
	charthtml+='<option value=0>Colour</option>';
	charthtml+='<option value=1>Plain</option>';
	charthtml+='</select>';
	charthtml+='</td>';
	charthtml+='</tr>';
	--- Colour selector end */
	charthtml+='<tr class="even">';
	charthtml+='<th width="40%">Layout for chart</th>';
	charthtml+='<td>';
	charthtml+='<select style="width:100px" class="input_option" onchange="changeChart(this,\''+multilabel+'\')" id="' + txtbase + '_Type">';
	charthtml+='<option value=0>Horizontal</option>';
	charthtml+='<option value=1>Vertical</option>';
	charthtml+='<option value=2>Pie</option>';
	charthtml+='</select>';
	charthtml+='</td>';
	charthtml+='</tr>';
	if(multilabel=="true"){
		charthtml+='<tr class="even">';
		charthtml+='<th width="40%">Grouping for chart</th>';
		charthtml+='<td>';
		charthtml+='<select style="width:100px" class="input_option" onchange="changeChart(this,\''+multilabel+'\')" id="' + txtbase + '_Group">';
		charthtml+='<option value=0>IP Address</option>';
		charthtml+='<option value=1>Country</option>';
		charthtml+='</select>';
		charthtml+='</td>';
		charthtml+='</tr>';
	}
	charthtml+='<tr>';
	charthtml+='<td colspan="2" style="padding: 2px;">';
	charthtml+='<div style="background-color:#2f3e44;border-radius:10px;width:735px;padding-left:5px;"><canvas id="divChart' + txtbase + '" height="360"></div>';
	charthtml+='</td>';
	charthtml+='</tr>';
	charthtml+='</table>';
	return charthtml;
}

function BuildTableHtml(txttitle,txtbase){
	var tablehtml='<div style="line-height:10px;">&nbsp;</div>';
	tablehtml+='<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable">';
	tablehtml+='<thead class="collapsible expanded" id="skynet_table_'+txtbase+'">';
	tablehtml+='<tr><td colspan="2">' + txttitle + ' (click to expand/collapse)</td></tr>';
	tablehtml+='</thead>';
	tablehtml+='<tr>';
	tablehtml+='<td colspan="2" align="center" style="padding: 0px;">';
	tablehtml+='<div class="collapsiblecontent">';
	tablehtml+='<table border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable StatsTable">';
	var nodata="";
	var objdataname = window["Label"+txtbase+"_IPs"];
	if(typeof objdataname === 'undefined' || objdataname === null){nodata="true"}
	if(objdataname.length == 0) {nodata="true"}
	if(objdataname.length == 1 && objdataname[0] == "") {nodata="true"}

	if(nodata == "true") {
		tablehtml+='<tr>';
		tablehtml+='<td colspan="4" class="nodata">';
		tablehtml+='No data to display';
		tablehtml+='</td>';
		tablehtml+='</tr>';
	} else {
		tablehtml+='<col style="width:100px;">';
		tablehtml+='<col style="width:200px;">';
		tablehtml+='<col style="width:85px;">';
		tablehtml+='<col style="width:60px;">';
		tablehtml+='<col style="width:175px">';
		tablehtml+='<thead>';
		tablehtml+='<tr>';
		tablehtml+='<th>IP Address </th>';
		tablehtml+='<th>Ban Reason</th>';
		tablehtml+='<th>AlienVault</th>';
		tablehtml+='<th>Country</th>';
		tablehtml+='<th>Associated Domains</th>';
		tablehtml+='</tr>';
		tablehtml+='</thead>';

		for(i = 0; i < objdataname.length; i++){
			tablehtml+='<tr>';
			tablehtml+='<td>'+window["Label"+txtbase+"_IPs"][i]+'</td>';
			tablehtml+='<td>'+window["Label"+txtbase+"_BanReason"][i]+'</td>';
			tablehtml+='<td><a target="_blank" href="'+window["Label"+txtbase+"_AlienVault"][i]+'">View Details</a></td>';
			tablehtml+='<td>'+window["Label"+txtbase+"_Country"][i]+'</td>';
			tablehtml+='<td style="white-space:pre;">'+window["Label"+txtbase+"_AssDomains"][i].replace(/ /g,"\n")+'</td>';
			tablehtml+='</tr>';
		};
	}
	tablehtml+='</table>'
	tablehtml+='</div>';
	tablehtml+='</td>';
	tablehtml+='</tr>';
	tablehtml+='</table>';
	return tablehtml;
}

</script>
</head>
<body onload="initial();">
<div id="TopBanner"></div>
<div id="Loading" class="popup_bg"></div>
<iframe name="hidden_frame" id="hidden_frame" src="" width="0" height="0" frameborder="0"></iframe>
<form method="post" name="form" id="ruleForm" action="/start_apply.htm" target="hidden_frame">
<input type="hidden" name="action_script" value="start_SkynetStats">
<input type="hidden" name="current_page" id="current_page" value="">
<input type="hidden" name="next_page" id="next_page" value="">
<input type="hidden" name="modified" value="0">
<input type="hidden" name="action_mode" value="apply">
<input type="hidden" name="action_wait" value="45">
<input type="hidden" name="first_time" value="">
<input type="hidden" name="SystemCmd" value="">
<input type="hidden" name="preferred_lang" id="preferred_lang" value="<% nvram_get("preferred_lang"); %>">
<input type="hidden" name="firmver" value="<% nvram_get("firmver"); %>">
<table class="content" align="center" cellpadding="0" cellspacing="0">
<tr>
<td width="17">&nbsp;</td>
<td valign="top" width="202">
<div id="mainMenu"></div>
<div id="subMenu"></div></td>
<td valign="top">
<div id="tabMenu" class="submenuBlock"></div>
<table width="98%" border="0" align="left" cellpadding="0" cellspacing="0">
<tr>
<td valign="top">
<table width="760px" border="0" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTitle" id="FormTitle">
<tbody>
<tr bgcolor="#4D595D">
<td valign="top">
<div style="line-height:10px;">&nbsp;</div>

<div class="formfonttitle" style="margin-bottom:0px;text-align:center;" id="statstitle">Skynet Statistics BETA</div>
<div style="line-height:5px;">&nbsp;</div>
<div class="formfonttitle" style="margin-bottom:0px;text-align:center;" id="statsdate">Last Updated - N/A</div>
<div style="line-height:5px;">&nbsp;</div>

<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable" style="border:0px;" id="skynet_table_buttons">
<tr class="apply_gen" valign="top" height="35px">
<td style="background-color:rgb(77, 89, 93);border:0px;">
<input type="button" onClick="applyRule();" value="Update Stats" class="button_gen" name="button">
</td>
</tr>
</table>

<div style="line-height:10px;">&nbsp;</div>

<!-- Key Stats starts here -->
<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3"  class="FormTable" id="skynet_table_keystats">
<thead class="collapsible expanded" id="skynet_keystats">
<tr>
<td colspan="4" id="keystats">Key Stats (click to expand/collapse)</td>
</tr>
</thead>
<tr>
<td colspan="2" align="center" style="padding: 0px;">
<div class="collapsiblecontent">
<table border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3"  class="FormTable StatsTable">
<col style="width:25%;">
<col style="width:25%;">
<col style="width:25%;">
<col style="width:25%;">
<thead>
<tr class="even" style="text-align:center;">
<th>IPs Banned</td>
<th>Ranges Banned</td>
<th>Inbound Blocks</td>
<th>Outbound Blocks</td>
</tr>
</thead>
<tr class="even" style="text-align:center;">
<td class="keystatsnumber" id="blcount1">IPs Banned</td>
<td class="keystatsnumber" id="blcount2">Ranges Banned</td>
<td class="keystatsnumber" id="hits1">Inbound Blocks</td>
<td class="keystatsnumber" id="hits2">Outbound Blocks</td>
</tr>
</table>
</div></td></tr>
</table>

<!-- Key Stats ends here -->

<!-- Custom tables and charts inserted here -->

<div style="line-height:10px;">&nbsp;</div>

</td>
</tr>
</tbody>
</table>
</form>
</td>
</tr>
</table>
</td>
<td width="10" align="center" valign="top">&nbsp;</td>
</tr>
</table>
<div id="footer">
</div>
</body>
</html>