<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">

<head>
    <meta http-equiv="X-UA-Compatible" content="IE=Edge" />
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <meta http-equiv="Pragma" content="no-cache" />
    <meta http-equiv="Expires" content="-1" />
    <link rel="shortcut icon" href="images/favicon.png" />
    <link rel="icon" href="images/favicon.png" />
    <title>Skynet Statistics</title>
    <link rel="stylesheet" type="text/css" href="index_style.css" />
    <link rel="stylesheet" type="text/css" href="form_style.css" />
    <style>
        /* Theme. */
        :root {
            --skynet-bg: #2f3e44;
            --skynet-panel: #354247;
            --skynet-panel-alt: #39484e;
            --skynet-border: #607780;
            --skynet-border-soft: #53666d;
            --skynet-text: #eef2f3;
            --skynet-muted: #b8c4c8;
            --skynet-heading: #dfe7ea;
            --skynet-link: #8fd1f5;
            --skynet-accent-muted: #9fc9d8;
            --skynet-title: #ffffff;
            --skynet-body: #d7e0e3;
            --skynet-muted-2: #aebcc1;
            --skynet-border-faint: rgba(155, 177, 185, 0.18);
            --skynet-border-medium: rgba(155, 177, 185, 0.34);
            --skynet-surface: #34464c;
            --skynet-surface-2: #2d3d43;
            --skynet-success: #a9e5bf;
            --skynet-warning: #f4d97b;
            --skynet-error: #f2afb5;
            --skynet-font-caption: 12px;
            --skynet-font-body: 12px;
            --skynet-font-label: 13px;
            --skynet-line-caption: 17px;
            --skynet-line-body: 17px;
        }

        /* Merlin page integration. */
        thead.collapsible {
            color: white;
            padding: 0px;
            width: 100%;
            border: none;
            text-align: left;
            outline: none;
            cursor: pointer;
        }

        .StatsTable {
            table-layout: fixed !important;
            width: 100% !important;
        }
        
        .StatsTable th {
            background-color: #1F2D35 !important;
            background: #2F3A3E !important;
            border-bottom: none !important;
            border-top: none !important;
            font-size: 12px !important;
            color: white !important;
            padding: 4px !important;
        }
        
        .StatsTable td {
            padding: 2px !important;
            word-wrap: break-word !important;
            overflow-wrap: break-word !important;
        }
        
        .StatsTable a {
            font-weight: bold !important;
            text-decoration: underline !important;
        }
        
        .StatsTable th:first-child,
        .StatsTable td:first-child {
            border-left: none !important;
        }
        
        .StatsTable th:last-child,
        .StatsTable td:last-child {
            border-right: none !important;
        }

        #FormTitle,
        #FormTitle > tbody > tr > td {
            width: 100% !important;
            max-width: 760px !important;
            min-width: 0 !important;
            box-sizing: border-box !important;
        }

        #FormTitle #skynet_dashboard,
        #FormTitle .skynet-section {
            width: 100% !important;
            max-width: 760px !important;
            min-width: 0 !important;
            box-sizing: border-box !important;
        }

        #FormTitle .skynet-chart-shell,
        #FormTitle .skynet-controls,
        #FormTitle .skynet-table-shell {
            max-width: 760px !important;
            min-width: 0 !important;
            box-sizing: border-box !important;
        }

        #FormTitle .skynet-chart-shell canvas {
            max-width: 100% !important;
        }

        #FormTitle table {
            box-sizing: border-box;
        }

        /* Header and summary. */
        #skynet_dashboard { margin:0 0 10px 0; }
        .skynet-hero {
            position:relative;
            overflow:hidden;
            background:
                radial-gradient(circle at 50% 130%,rgba(73,171,207,0.18),transparent 55%),
                repeating-linear-gradient(90deg,rgba(121,183,211,0.025) 0,rgba(121,183,211,0.025) 1px,transparent 1px,transparent 24px),
                linear-gradient(180deg,#35454b 0%,#28363b 100%);
            border:1px solid #63879a;
            border-radius:6px;
            padding:16px 110px 14px 110px;
            margin-bottom:10px;
            box-shadow:
                inset 0 1px 0 rgba(255,255,255,0.08),
                inset 0 -1px 0 rgba(48,120,151,0.12),
                0 1px 2px rgba(0,0,0,0.18);
            text-align:center;
        }

        .skynet-hero::before {
            content:"";
            position:absolute;
            top:0;
            right:0;
            bottom:0;
            left:0;
            background:repeating-linear-gradient(0deg,transparent 0,transparent 4px,rgba(0,0,0,0.045) 5px);
            pointer-events:none;
        }

        .skynet-hero::after {
            content:"";
            position:absolute;
            right:14%;
            bottom:0;
            left:14%;
            height:1px;
            background:linear-gradient(90deg,transparent,#78c6e7,transparent);
            opacity:0.75;
        }

        .skynet-hero-core {
            position:relative;
            z-index:1;
        }

        .skynet-hero-title {
            display:inline-block;
            position:relative;
            color:#ffffff !important;
            font-family:monospace;
            font-size:23px;
            font-weight:bold;
            letter-spacing:4px;
            line-height:27px;
            text-shadow:0 0 10px rgba(121,198,231,0.22),0 1px 1px rgba(0,0,0,0.3);
            padding-bottom:4px;
        }

        .skynet-hero-title::after {
            content:"";
            display:block;
            width:48px;
            height:1px;
            margin:3px auto 0 auto;
            background:linear-gradient(90deg,transparent,#78c6e7,transparent);
            box-shadow:0 0 5px rgba(120,198,231,0.45);
        }

        .skynet-hero-sub {
            margin-top:1px;
            color:#bfcacd !important;
            font-family:monospace;
            font-size:var(--skynet-font-body);
            letter-spacing:0.45px;
            line-height:var(--skynet-line-body);
        }

        .skynet-status {
            position:absolute;
            top:11px;
            right:12px;
            margin:0;
            padding:5px 10px;
            border-radius:12px;
            background:linear-gradient(180deg,#385344 0%,#2d4337 100%);
            color:#a9e5bf;
            border:1px solid #4c8061;
            font-weight:bold;
            font-size:var(--skynet-font-body);
            box-shadow:inset 0 1px 0 rgba(255,255,255,0.08),0 1px 3px rgba(0,0,0,0.24);
            z-index:2;
        }
        .skynet-status-dot {
            display:inline-block; width:7px; height:7px; border-radius:50%;
            background:#65c18c; margin-right:5px;
            box-shadow:0 0 5px rgba(101,193,140,0.5);
        }

        .skynet-project-link {
            position:absolute;
            top:11px;
            left:12px;
            padding:5px 10px;
            border:1px solid #547d93;
            border-radius:12px;
            background:linear-gradient(180deg,#354f5b 0%,#2b4049 100%);
            color:#9fd5f1 !important;
            font-size:var(--skynet-font-body);
            font-weight:bold;
            text-decoration:none;
            box-shadow:inset 0 1px 0 rgba(255,255,255,0.06),0 1px 3px rgba(0,0,0,0.22);
            z-index:2;
        }

        .skynet-project-link:hover,
        .skynet-project-link:focus-visible {
            border-color:#79b7d3;
            background:#344e5a;
            color:#d1efff !important;
            outline:none;
        }
        .skynet-kpis {
            width:100%; border-collapse:separate !important;
            border-spacing:6px !important; margin:-6px 0 4px -6px;
        }
        .skynet-kpi {
            background:linear-gradient(180deg,#39484e 0%,#344247 100%) !important;
            border:1px solid #607780 !important;
            border-radius:5px; text-align:center; padding:9px 5px !important;
            width:25%;
            box-shadow:inset 0 1px 0 rgba(255,255,255,0.035),0 1px 2px rgba(0,0,0,0.12);
            transition:border-color 140ms ease,transform 140ms ease;
        }
        .skynet-kpi:hover {
            border-color:#7594a0 !important;
            transform:translateY(-1px);
        }
        .skynet-kpi-label {
            display:block; color:var(--skynet-muted-2) !important; font-size:var(--skynet-font-body); font-weight:bold;
        }
        .skynet-kpi-value {
            display:block; color:var(--skynet-title) !important; font-size:22px; line-height:25px;
            font-weight:bold; margin-top:3px;
        }
        .skynet-meta {
            display:flex;
            flex:0 0 auto;
            flex-wrap:nowrap;
            align-items:baseline;
            gap:12px;
            margin:0;
            color:var(--skynet-muted-2) !important;
        }
        .skynet-meta-item {
            display:flex;
            align-items:baseline;
            gap:5px;
            min-width:0;
            padding:0;
        }
        .skynet-meta-label {
            color:var(--skynet-accent-muted) !important;
            font-size:var(--skynet-font-caption);
            font-weight:bold;
            letter-spacing:0.35px;
            line-height:var(--skynet-line-caption);
            text-transform:uppercase;
            white-space:nowrap;
        }
        .skynet-meta-value {
            overflow:hidden;
            color:#c5d0d4 !important;
            font-family:Arial,sans-serif;
            font-size:var(--skynet-font-caption);
            line-height:var(--skynet-line-caption);
            text-overflow:ellipsis;
            white-space:nowrap;
        }
        .skynet-meta-period {
            padding-left:7px;
            border-left:2px solid #5799b4;
        }
        .skynet-meta-period .skynet-meta-value {
            color:#e1edf1 !important;
            font-size:var(--skynet-font-caption);
            font-weight:bold;
            letter-spacing:0.1px;
        }
        .skynet-meta-log {
            padding-left:11px;
            border-left:1px solid rgba(126,153,163,0.28);
        }
        .skynet-meta-log .skynet-meta-value {
            color:#d3e0e4 !important;
            font-size:var(--skynet-font-caption);
            font-weight:bold;
            letter-spacing:0.1px;
        }
        .skynet-update-result {
            flex:1 1 auto;
            min-width:0;
            overflow:hidden;
            min-height:0;
            margin:0;
            padding-left:10px;
            border-left:1px solid rgba(126,153,163,0.28);
            color:#b8c4c8;
            font-size:var(--skynet-font-body);
            line-height:15px;
            text-overflow:ellipsis;
            white-space:nowrap;
        }
        .skynet-update-result:empty { display:none; }
        .skynet-update-result.error { color:var(--skynet-error); }
        .skynet-actionbar {
            padding:0 !important;
            border:0 !important;
            background:transparent !important;
        }

        /* Navigation and settings. */
        .skynet-tabs {
            display: flex;
            gap: 3px;
            margin: 0 0 10px 0;
            padding: 4px;
            border: 1px solid var(--skynet-border-soft);
            border-radius: 6px;
            background: #2c3b40;
            box-shadow: inset 0 1px 2px rgba(0,0,0,0.24);
        }

        .skynet-tab {
            flex: 1 1 0;
            min-width: 0;
            min-height: 32px;
            padding: 6px;
            border: 1px solid transparent;
            border-bottom: 2px solid transparent;
            border-radius: 4px;
            background: transparent !important;
            color: var(--skynet-muted) !important;
            font-size: var(--skynet-font-body);
            font-weight: bold;
            line-height: 16px;
            cursor: pointer;
            transition: background-color 140ms ease,border-color 140ms ease,
                        color 140ms ease,box-shadow 140ms ease;
        }

        .skynet-tab:hover,
        .skynet-tab.active {
            color: var(--skynet-text) !important;
            background: rgba(255,255,255,0.045) !important;
        }

        .skynet-tab.active {
            border-color: #526d78;
            border-bottom-color: var(--skynet-link);
            background: linear-gradient(180deg,#3b5058 0%,#34474e 100%) !important;
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.05),
                        0 1px 2px rgba(0,0,0,0.18);
        }

        .skynet-tab:focus-visible {
            outline: 2px solid var(--skynet-link);
            outline-offset: -2px;
        }

        .skynet-view-hidden {
            display: none;
        }


        .skynet-update-bar {
            display:grid;
            grid-template-columns:minmax(0,1fr) auto;
            align-items: center;
            gap:10px;
            min-height:44px;
            margin: 8px 0 10px 0;
            padding:7px 9px;
            background:#34464c;
            border:1px solid #566d76;
            border-radius:5px;
            box-shadow:inset 0 1px 0 rgba(255,255,255,0.025);
            box-sizing: border-box;
            width: 100%;
            max-width: 760px;
        }

        .skynet-update-info {
            display:flex;
            align-items:center;
            gap:10px;
            min-width: 0;
            color: var(--skynet-muted-2) !important;
            font-size: var(--skynet-font-body);
            line-height: var(--skynet-line-body);
        }

        .skynet-update-control {
            position:relative;
            width:116px;
            flex:none;
        }

        .skynet-update-control .skynet-update-button {
            width:100%;
            min-width:0;
            height:28px;
            padding:0 10px !important;
            border-color:#667f89 !important;
            border-radius:4px !important;
            background:linear-gradient(180deg,#4a626b 0%,#40565e 100%) !important;
            color:#e4edf0 !important;
            font-family:Arial,sans-serif !important;
            font-size:var(--skynet-font-body) !important;
            line-height:26px !important;
            text-shadow:none;
            box-shadow:inset 0 1px 0 rgba(255,255,255,0.055);
            white-space:nowrap;
        }

        .skynet-update-control .skynet-update-button:not(:disabled):hover {
            border-color:#7d9aa6 !important;
            background:linear-gradient(180deg,#526d77 0%,#465e67 100%) !important;
        }

        .skynet-update-button {
            min-width: 112px;
            height: 32px;
            padding: 0 14px !important;
            border: 1px solid #8ab0c2 !important;
            border-radius: 5px !important;
            background: linear-gradient(180deg, #6ea6bf 0%, #4f7f95 100%) !important;
            color: #fff !important;
            font-weight: bold !important;
            line-height: 30px !important;
            text-align: center !important;
            vertical-align: middle;
            text-shadow: 0 1px 1px rgba(0,0,0,0.35);
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.12),
                        0 1px 2px rgba(0,0,0,0.20);
            cursor: pointer;
            transition: transform 120ms ease, filter 120ms ease;
        }

        .skynet-update-button:disabled {
            opacity: 0.72;
            cursor: default;
            filter: saturate(0.75);
        }

        .skynet-update-button.skynet-update-busy {
            cursor: wait;
        }

        .skynet-update-button:not(:disabled):hover {
            filter: brightness(1.08);
        }

        .skynet-update-button:not(:disabled):active {
            transform: translateY(1px);
        }

        .skynet-update-button:focus-visible {
            outline: 2px solid #8fd1f5;
            outline-offset: 2px;
        }

        .skynet-settings-reload {
            border-color: var(--skynet-border) !important;
            background: var(--skynet-panel-alt) !important;
            color: var(--skynet-heading) !important;
            box-shadow: none;
            text-shadow: none;
        }

        .skynet-settings {
            margin: 10px 0;
            overflow: hidden;
            border: 1px solid var(--skynet-border-medium);
            border-radius: 6px;
            background: var(--skynet-surface);
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.025),
                        0 1px 3px rgba(0,0,0,0.14);
        }

        .skynet-settings-section-hidden {
            display: none;
        }

        .skynet-settings-table {
            margin: 0 !important;
            border: 0 !important;
        }

        .skynet-settings-table th {
            width: 42%;
        }

        .skynet-settings-table tr:not(.skynet-settings-group) > th,
        .skynet-settings-table tr:not(.skynet-settings-group) > td {
            padding: 6px 10px !important;
            border-color: var(--skynet-border-soft) !important;
            vertical-align: middle;
            transition: background-color 120ms ease;
        }

        .skynet-settings-table tr:not(.skynet-settings-group) > th {
            background: #2f3e44 !important;
        }

        .skynet-settings-table tr:not(.skynet-settings-group) > td {
            background: #35474d !important;
        }

        .skynet-settings-table tr:not(.skynet-settings-group):hover > th {
            background: #33454b !important;
        }

        .skynet-settings-table tr:not(.skynet-settings-group):hover > td {
            background: #3a4d54 !important;
        }

        #FormTitle .skynet-settings-group th {
            width: auto;
            padding: 8px 10px;
            border-color: var(--skynet-border-soft) !important;
            border-left: 3px solid #6da7be !important;
            background: linear-gradient(90deg,#38505a 0%,#35464d 62%,#34444b 100%);
            color: var(--skynet-accent-muted) !important;
            font-size: var(--skynet-font-body);
            line-height: 15px;
            letter-spacing: 0.6px;
            text-transform: uppercase;
        }

        #FormTitle .skynet-setting-name,
        #FormTitle .skynet-setting-help {
            display: block;
        }

        #FormTitle .skynet-setting-name {
            color: var(--skynet-heading) !important;
            font-size: var(--skynet-font-label);
            font-weight: bold;
            line-height: var(--skynet-line-body);
        }

        #FormTitle .skynet-setting-help {
            margin-top: 3px;
            color: var(--skynet-muted) !important;
            font-size: var(--skynet-font-body);
            font-weight: normal;
            line-height: 15px;
        }

        .skynet-settings-table select {
            width: 280px;
            max-width: 100%;
            height: 30px;
            padding: 0 24px 0 8px;
            border: 1px solid #70858d;
            border-radius: 4px;
            background-color: #536970;
            color: #ffffff;
            text-align: center;
            text-align-last: center;
            box-shadow: inset 0 1px 2px rgba(0,0,0,0.22);
            box-sizing: border-box;
            transition: border-color 120ms ease,box-shadow 120ms ease;
        }

        .skynet-settings-table select:hover {
            border-color: #8aa4ae;
        }

        .skynet-settings-table select:focus {
            outline: none;
            border-color: var(--skynet-link);
            box-shadow: 0 0 0 2px rgba(143,209,245,0.15),
                        inset 0 1px 2px rgba(0,0,0,0.18);
        }

        .skynet-malware-controls {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .skynet-malware-status {
            display: block;
            margin-top: 5px;
            padding: 0 !important;
            border: 0 !important;
            background: transparent !important;
            color: var(--skynet-muted) !important;
            font-size: var(--skynet-font-body);
            line-height: 15px;
        }

        .skynet-malware-update {
            min-width: 96px;
            height: 30px;
        }

        .skynet-feed-manager {
            overflow: hidden;
            border: 1px solid var(--skynet-border-soft);
            border-radius: 5px;
            background: linear-gradient(180deg, #304148 0%, #2d3d43 100%);
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.03),
                        0 1px 2px rgba(0,0,0,0.16);
        }

        .skynet-feed-container > td {
            padding: 6px 10px !important;
        }

        .skynet-feed-intro {
            padding: 10px 10px 9px;
            border-bottom: 1px solid var(--skynet-border-soft);
            background: rgba(255,255,255,0.025);
        }

        .skynet-feed-title,
        .skynet-feed-help {
            display: block;
        }

        .skynet-feed-title {
            padding: 0 !important;
            border: 0 !important;
            background: transparent !important;
            color: var(--skynet-title) !important;
            font-size: var(--skynet-font-label);
            font-weight: bold;
            line-height: var(--skynet-line-body);
        }

        .skynet-feed-help {
            margin-top: 2px;
            padding: 0 !important;
            border: 0 !important;
            background: transparent !important;
            color: var(--skynet-muted) !important;
            font-size: var(--skynet-font-body);
            line-height: 15px;
        }

        .skynet-feed-header,
        .skynet-feed-row {
            display: grid;
            grid-template-columns: minmax(0, 1fr) 76px 140px 68px 54px;
            align-items: center;
            gap: 10px;
        }

        .skynet-feed-header {
            padding: 7px 10px;
            border-bottom: 1px solid var(--skynet-border-soft);
            background: #29383e;
            color: var(--skynet-accent-muted);
            font-size: var(--skynet-font-caption);
            letter-spacing: 0.4px;
            line-height: var(--skynet-line-caption);
            text-transform: uppercase;
        }

        .skynet-feed-header > span {
            display: block;
            padding: 0 !important;
            border: 0 !important;
            background: transparent !important;
            color: inherit !important;
        }

        .skynet-feed-row {
            min-height: 36px;
            padding: 7px 10px;
            border-top: 1px solid var(--skynet-border-soft);
            box-sizing: border-box;
            line-height: 16px;
            transition: background-color 120ms ease;
        }

        .skynet-feed-row:first-child {
            border-top: 0;
        }

        .skynet-feed-row:nth-child(even) {
            background: rgba(255,255,255,0.018);
        }

        .skynet-feed-row:hover {
            background: rgba(112,181,212,0.07);
        }

        #FormTitle .skynet-feed-source {
            min-width: 0;
            overflow: hidden;
            color: var(--skynet-text) !important;
            font-family: monospace;
            font-size: var(--skynet-font-body);
            line-height: var(--skynet-line-body);
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        #FormTitle .skynet-feed-entries,
        #FormTitle .skynet-feed-success,
        #FormTitle .skynet-feed-success > span {
            color: var(--skynet-muted-2) !important;
            font-size: var(--skynet-font-body);
            font-variant-numeric: tabular-nums;
            line-height: var(--skynet-line-body);
        }

        #FormTitle .skynet-feed-change {
            display: block;
            color: var(--skynet-muted) !important;
            font-size: var(--skynet-font-caption);
            line-height: var(--skynet-line-caption);
        }

        .skynet-feed-header > span:nth-child(2),
        .skynet-feed-entries {
            text-align: right;
        }

        .skynet-feed-header > span:nth-child(3),
        .skynet-feed-success {
            text-align: center;
        }

        .skynet-feed-header > span:nth-child(4),
        .skynet-feed-header > span:nth-child(5) {
            text-align: center;
        }

        .skynet-feed-state {
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .skynet-feed-pill {
            display: inline-block;
            min-width: 48px;
            padding: 3px 6px;
            border: 1px solid var(--skynet-border);
            border-radius: 10px;
            background: var(--skynet-panel-alt);
            color: var(--skynet-muted-2);
            font-size: var(--skynet-font-caption);
            font-weight: bold;
            line-height: var(--skynet-line-caption);
            text-align: center;
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.07),
                        0 1px 2px rgba(0,0,0,0.24);
        }

        .skynet-feed-pill.current {
            border-color: #4c8061;
            background: linear-gradient(180deg,#385344 0%,#2d4337 100%);
            color: var(--skynet-success);
        }

        .skynet-feed-pill.cached {
            border-color: #8b7841;
            background: linear-gradient(180deg,#554d36 0%,#443e2d 100%);
            color: var(--skynet-warning);
        }

        .skynet-feed-pill.empty,
        .skynet-feed-pill.pending {
            border-color: #58727d;
            background: linear-gradient(180deg,#3d5058 0%,#33434a 100%);
            color: #aac7d2;
        }

        .skynet-feed-pill.expired {
            border-color: #8a6654;
            background: linear-gradient(180deg,#57463d 0%,#473a34 100%);
            color: #e3ad8f;
        }

        .skynet-feed-pill.failed {
            border-color: #8a5057;
            background: linear-gradient(180deg,#583c41 0%,#473136 100%);
            color: var(--skynet-error);
        }

        .skynet-feed-toggle {
            position: relative;
            display: flex;
            justify-content: center;
            width: 36px;
            height: 20px;
            margin: 0 auto;
            cursor: pointer;
        }

        .skynet-feed-toggle input {
            position: absolute;
            width: 1px;
            height: 1px;
            opacity: 0;
        }

        .skynet-feed-switch {
            position: absolute;
            top: 0;
            right: 0;
            bottom: 0;
            left: 0;
            border: 1px solid #667980;
            border-radius: 10px;
            background: #25343a;
            box-shadow: inset 0 1px 2px rgba(0,0,0,0.35);
            transition: background-color 140ms ease, border-color 140ms ease;
        }

        .skynet-feed-switch::after {
            content: "";
            position: absolute;
            top: 2px;
            left: 2px;
            width: 14px;
            height: 14px;
            border-radius: 50%;
            background: #a8b5ba;
            box-shadow: 0 1px 2px rgba(0,0,0,0.35);
            transition: left 140ms ease, background-color 140ms ease;
        }

        .skynet-feed-toggle input:checked + .skynet-feed-switch {
            border-color: #70aec8;
            background: #477d94;
        }

        .skynet-feed-toggle input:checked + .skynet-feed-switch::after {
            left: 18px;
            background: #e9f7fc;
        }

        .skynet-feed-toggle input:focus-visible + .skynet-feed-switch {
            outline: 2px solid var(--skynet-link);
            outline-offset: 2px;
        }

        .skynet-feed-toggle input:disabled + .skynet-feed-switch {
            opacity: 0.55;
            cursor: default;
        }

        .skynet-feed-empty,
        .skynet-feed-status {
            color: var(--skynet-muted);
            font-size: var(--skynet-font-body);
            line-height: 15px;
        }

        .skynet-feed-empty {
            padding: 8px 10px;
        }

        .skynet-feed-actions {
            display: flex;
            align-items: center;
            justify-content: flex-end;
            gap: 8px;
            padding: 8px 10px;
            border-top: 1px solid var(--skynet-border-soft);
            background: rgba(0,0,0,0.08);
        }

        .skynet-feed-status {
            flex: 1;
            padding: 0 !important;
            border: 0 !important;
            background: transparent !important;
            color: var(--skynet-muted) !important;
        }

        .skynet-feed-status.error {
            color: var(--skynet-error) !important;
        }

        .skynet-feed-status.warning {
            color: var(--skynet-warning) !important;
        }

        .skynet-settings-result.warning {
            color: var(--skynet-warning);
        }

        .skynet-country-status.warning {
            color: var(--skynet-warning) !important;
        }

        .skynet-settings-table input[type="number"] {
            width: 82px;
        }

        .skynet-settings-table input[type="url"] {
            width: 100%;
            max-width: 360px;
        }

        .skynet-settings-table input[type="text"] {
            width: 100%;
            max-width: 360px;
        }

        .skynet-settings-table input[type="number"],
        .skynet-settings-table input[type="url"],
        .skynet-settings-table input[type="text"] {
            height: 30px;
            padding: 5px 9px;
            border: 1px solid var(--skynet-border);
            border-radius: 4px;
            background: var(--skynet-bg);
            color: var(--skynet-text);
            box-shadow: inset 0 1px 2px rgba(0,0,0,0.28);
            box-sizing: border-box;
            transition: border-color 0.15s ease, box-shadow 0.15s ease;
        }

        .skynet-settings-table input[type="number"]::placeholder,
        .skynet-settings-table input[type="url"]::placeholder,
        .skynet-settings-table input[type="text"]::placeholder {
            color: var(--skynet-muted);
            opacity: 0.9;
        }

        .skynet-settings-table input[type="number"]:hover,
        .skynet-settings-table input[type="url"]:hover,
        .skynet-settings-table input[type="text"]:hover {
            border-color: var(--skynet-heading);
        }

        .skynet-settings-table input[type="number"]:focus,
        .skynet-settings-table input[type="url"]:focus,
        .skynet-settings-table input[type="text"]:focus {
            outline: none;
            border-color: var(--skynet-link);
            box-shadow: 0 0 0 2px rgba(143,209,245,0.18),
                inset 0 1px 2px rgba(0,0,0,0.2);
        }

        .skynet-number-control {
            display: flex;
            align-items: center;
            gap: 7px;
        }

        .skynet-input-note {
            padding: 0 !important;
            border: 0 !important;
            background: transparent !important;
            color: var(--skynet-muted) !important;
            font-size: var(--skynet-font-body);
            line-height: 15px;
        }

        .skynet-country-editor {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .skynet-country-row th {
            padding-top: 10px !important;
            vertical-align: top;
        }

        .skynet-country-picker {
            width: 100% !important;
            max-width: 360px !important;
        }

        #FormTitle .skynet-country-tag {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            min-height: 25px;
            padding: 0 5px 0 8px;
            border: 1px solid #5d7f8c;
            border-radius: 13px;
            background: linear-gradient(180deg,#3c5964 0%,#304750 100%);
            color: var(--skynet-text) !important;
            font-size: var(--skynet-font-body);
            line-height: 15px;
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.07),
                        0 1px 2px rgba(0,0,0,0.24);
            transition: transform 120ms ease,border-color 120ms ease,
                        box-shadow 120ms ease;
        }

        #FormTitle .skynet-country-tag:hover {
            border-color: #79aabd;
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.09),
                        0 2px 4px rgba(0,0,0,0.28);
            transform: translateY(-1px);
        }

        #FormTitle .skynet-country-tag::before,
        .skynet-rule-tag::before {
            content: "";
            flex: 0 0 auto;
            width: 5px;
            height: 5px;
            border-radius: 50%;
            background: #74bfdc;
            box-shadow: 0 0 5px rgba(116,191,220,0.48);
        }

        #FormTitle .skynet-country-tag > span {
            color: var(--skynet-text) !important;
        }

        .skynet-country-remove {
            width: 22px;
            height: 22px;
            padding: 0;
            border: 0;
            border-radius: 50%;
            background: transparent;
            color: var(--skynet-muted);
            font-size: 15px;
            line-height: 22px;
            cursor: pointer;
        }

        .skynet-country-remove:hover,
        .skynet-country-remove:focus-visible {
            background: rgba(255,95,109,0.18);
            color: #ff9ca6;
            outline: none;
        }

        .skynet-country-empty,
        .skynet-country-status {
            color: var(--skynet-muted);
            font-size: var(--skynet-font-body);
            line-height: 15px;
        }

        .skynet-country-empty {
            padding: 0 !important;
            border: 0 !important;
            background: transparent !important;
            color: var(--skynet-muted) !important;
        }

        .skynet-country-status.error {
            color: var(--skynet-error);
        }

        .skynet-country-health,
        .skynet-rules-manager {
            overflow: hidden;
            border: 1px solid var(--skynet-border-soft);
            border-radius: 5px;
            background: linear-gradient(180deg, #304148 0%, #2d3d43 100%);
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.03),
                        0 1px 2px rgba(0,0,0,0.16);
        }

        .skynet-country-health-header,
        .skynet-country-health-row {
            display: grid;
            grid-template-columns: minmax(0, 1fr) 72px 140px 68px 52px;
            align-items: center;
            gap: 10px;
        }

        .skynet-country-health-header {
            padding: 7px 10px;
            border-bottom: 1px solid var(--skynet-border-soft);
            background: #29383e;
            color: var(--skynet-accent-muted);
            font-size: var(--skynet-font-caption);
            letter-spacing: 0.4px;
            line-height: var(--skynet-line-caption);
            text-transform: uppercase;
        }

        .skynet-country-health-header[hidden] {
            display: none;
        }

        .skynet-country-health-row {
            min-height: 34px;
            padding: 6px 10px;
            border-top: 1px solid var(--skynet-border-soft);
            color: var(--skynet-muted-2);
            font-size: var(--skynet-font-body);
            line-height: var(--skynet-line-body);
        }

        .skynet-country-health-row:first-child {
            border-top: 0;
        }

        .skynet-country-health-row:nth-child(even) {
            background: rgba(255,255,255,0.018);
        }

        .skynet-country-health-row:hover,
        .skynet-rule-row:hover {
            background: rgba(112,181,212,0.07);
        }

        #FormTitle .skynet-country-health-header > span {
            color: inherit !important;
            padding: 0 !important;
        }

        #FormTitle .skynet-country-health-row > span {
            color: var(--skynet-muted-2) !important;
            padding: 0 !important;
        }

        #FormTitle .skynet-country-health-row > .skynet-country-health-name {
            min-width: 0;
            overflow: hidden;
            color: var(--skynet-text) !important;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .skynet-country-health-count,
        .skynet-country-health-date {
            font-variant-numeric: tabular-nums;
        }

        .skynet-country-health-date {
            min-width: 0;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .skynet-country-health-header > span:nth-child(2),
        .skynet-country-health-header > span:nth-child(4),
        .skynet-country-health-header > span:nth-child(5),
        .skynet-country-health-count,
        .skynet-country-health-state,
        .skynet-country-health-remove {
            text-align: center;
        }

        .skynet-country-health-remove {
            justify-self: center;
        }

        .skynet-rules-container > td,
        .skynet-country-health-container > td {
            padding: 6px 10px !important;
        }

        .skynet-rules-toolbar,
        .skynet-rules-filterbar,
        .skynet-rules-actions {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 8px 10px;
        }

        .skynet-rules-toolbar {
            align-items: flex-end;
            flex-wrap: wrap;
            column-gap: 10px;
            row-gap: 8px;
        }

        .skynet-rule-field {
            display: flex;
            flex: 1 1 130px;
            flex-direction: column;
            gap: 4px;
            min-width: 110px;
        }

        .skynet-rule-field-entries {
            flex-basis: 240px;
        }

        #FormTitle .skynet-rule-label {
            box-sizing: border-box;
            color: var(--skynet-accent-muted) !important;
            font-size: var(--skynet-font-caption);
            line-height: var(--skynet-line-caption);
            letter-spacing: 0.3px;
            padding: 0 6px !important;
            border: 0 !important;
            background: transparent !important;
            text-transform: uppercase;
        }

        .skynet-rule-field input,
        .skynet-rule-field select,
        .skynet-rules-search {
            width: 100% !important;
            max-width: none !important;
        }

        .skynet-rule-tags {
            display: flex;
            flex-wrap: wrap;
            gap: 5px;
            min-height: 25px;
            padding: 0 10px 8px;
        }

        .skynet-rule-tag {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            min-height: 24px;
            padding: 0 5px 0 8px;
            border: 1px solid #5d7f8c;
            border-radius: 12px;
            background: linear-gradient(180deg,#3c5964 0%,#304750 100%);
            color: var(--skynet-text);
            font-family: monospace;
            font-size: var(--skynet-font-body);
            line-height: 15px;
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.07),
                        0 1px 2px rgba(0,0,0,0.24);
            transition: transform 120ms ease,border-color 120ms ease,
                        box-shadow 120ms ease;
        }

        .skynet-rule-tag:hover {
            border-color: #79aabd;
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.09),
                        0 2px 4px rgba(0,0,0,0.28);
            transform: translateY(-1px);
        }

        .skynet-rules-filterbar {
            border-top: 1px solid var(--skynet-border-soft);
            border-bottom: 1px solid var(--skynet-border-soft);
            background: rgba(0,0,0,0.08);
        }

        .skynet-rule-filter {
            min-width: 92px;
        }

        .skynet-rules-search {
            margin-left: auto;
        }

        .skynet-rule-header,
        .skynet-rule-row {
            display: grid;
            grid-template-columns: 108px minmax(0, 1fr) minmax(110px, 0.8fr) 62px 70px;
            align-items: center;
            gap: 10px;
        }

        .skynet-rule-header {
            padding: 7px 10px;
            background: #29383e;
            color: var(--skynet-accent-muted);
            font-size: var(--skynet-font-caption);
            letter-spacing: 0.4px;
            line-height: var(--skynet-line-caption);
            text-transform: uppercase;
        }

        #FormTitle .skynet-rule-header > span {
            color: inherit !important;
            padding: 0 !important;
        }

        #FormTitle .skynet-rule-header > span:nth-child(4),
        #FormTitle .skynet-rule-header > span:nth-child(5) {
            text-align: center;
        }

        .skynet-rule-row {
            min-height: 36px;
            padding: 7px 10px;
            border-top: 1px solid var(--skynet-border-soft);
            color: var(--skynet-muted-2);
            font-size: var(--skynet-font-body);
            line-height: var(--skynet-line-body);
        }

        #FormTitle .skynet-rule-row > span {
            color: var(--skynet-muted-2) !important;
            padding: 0 !important;
        }

        /* Keep grid text aligned while removing Merlin's default span tiles. */
        #FormTitle .skynet-feed-header > span,
        #FormTitle .skynet-feed-row > span,
        #FormTitle .skynet-country-health-header > span,
        #FormTitle .skynet-country-health-row > span,
        #FormTitle .skynet-rule-header > span,
        #FormTitle .skynet-rule-row > span {
            box-sizing: border-box;
            padding: 0 6px !important;
            border: 0 !important;
            background: transparent !important;
        }

        /* Parent components provide the visual treatment for nested text. */
        #FormTitle .skynet-context-link > span,
        #FormTitle .skynet-table-domains > span,
        #FormTitle .skynet-feed-success > span,
        #FormTitle .skynet-country-tag > span,
        #FormTitle .skynet-rules-actions > .skynet-country-status {
            padding: 0 !important;
            border: 0 !important;
            background: transparent !important;
            box-shadow: none !important;
        }

        .skynet-rule-row:nth-child(even) {
            background: rgba(255,255,255,0.018);
        }

        #FormTitle .skynet-rule-row > .skynet-rule-type {
            color: var(--skynet-heading) !important;
        }

        #FormTitle .skynet-rule-row > .skynet-rule-type.ban {
            color: var(--skynet-error) !important;
        }

        #FormTitle .skynet-rule-row > .skynet-rule-type.whitelist {
            color: var(--skynet-success) !important;
        }

        .skynet-rule-entry,
        .skynet-rule-comment {
            min-width: 0;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        #FormTitle .skynet-rule-row > .skynet-rule-entry {
            color: var(--skynet-text) !important;
            font-family: monospace;
        }

        .skynet-rule-count {
            text-align: center;
        }

        .skynet-rule-remove {
            min-width: 62px !important;
            padding-right: 6px !important;
            padding-left: 6px !important;
            font-size: var(--skynet-font-body) !important;
            white-space: nowrap;
        }

        .skynet-rules-actions {
            justify-content: flex-end;
            border-top: 1px solid var(--skynet-border-soft);
            background: rgba(0,0,0,0.08);
        }

        .skynet-rules-actions .skynet-country-status {
            flex: 1;
        }

        .skynet-rule-overview {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 8px 10px;
            border-top: 1px solid var(--skynet-border-soft);
            border-bottom: 1px solid var(--skynet-border-soft);
            background: rgba(0,0,0,0.08);
        }

        .skynet-rule-health {
            display: flex;
            flex: 1;
            align-items: center;
            flex-wrap: wrap;
            gap: 6px;
            min-width: 0;
            color: var(--skynet-muted-2);
            font-size: var(--skynet-font-body);
        }

        #FormTitle .skynet-rule-health > span {
            padding: 0 !important;
            border: 0 !important;
            background: transparent !important;
            box-shadow: none !important;
        }

        #FormTitle .skynet-rule-freshness > span,
        #FormTitle .skynet-action-header > span,
        #FormTitle .skynet-action-row > span {
            padding: 0 !important;
            border: 0 !important;
            background: transparent !important;
            box-shadow: none !important;
        }

        .skynet-rule-freshness {
            display: flex;
            align-items: center;
            gap: 6px;
            min-width: 0;
        }

        .skynet-rule-age {
            min-width: 0;
            overflow: hidden;
            color: var(--skynet-muted) !important;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .skynet-rule-health-time {
            color: var(--skynet-muted) !important;
            font-variant-numeric: tabular-nums;
        }

        .skynet-action-header,
        .skynet-action-row {
            display: grid;
            grid-template-columns: 120px 84px 150px minmax(0, 1fr);
            align-items: center;
            gap: 10px;
            padding: 8px 12px;
        }

        .skynet-action-panel {
            overflow: hidden;
            margin-top: 10px;
            border: 1px solid var(--skynet-border-soft);
            border-radius: 5px;
            background: rgba(25,39,44,0.34);
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.025);
        }

        .skynet-action-intro {
            padding: 10px 12px !important;
            border: 0 !important;
            border-bottom: 1px solid var(--skynet-border-soft) !important;
            background: linear-gradient(180deg,rgba(69,91,99,0.30),rgba(38,53,59,0.18));
        }

        #FormTitle .skynet-action-intro .skynet-feed-title {
            display: flex;
            align-items: center;
            gap: 7px;
            color: var(--skynet-heading) !important;
        }

        .skynet-action-intro .skynet-feed-title::before {
            content: "";
            width: 7px;
            height: 7px;
            flex: 0 0 7px;
            border-radius: 50%;
            background: #79c6e7;
            box-shadow: 0 0 6px rgba(121,198,231,0.5);
        }

        .skynet-action-header {
            background: rgba(29,44,50,0.82);
            border-bottom: 1px solid var(--skynet-border-soft);
            font-size: var(--skynet-font-caption);
            line-height: var(--skynet-line-caption);
            letter-spacing: 0.35px;
            text-transform: uppercase;
        }

        #FormTitle .skynet-action-header > span {
            color: var(--skynet-accent-muted) !important;
            font-weight: 600;
            text-align: left;
        }

        .skynet-action-row {
            position: relative;
            min-height: 38px;
            border-top: 1px solid var(--skynet-border-faint);
            color: var(--skynet-muted-2);
            font-size: var(--skynet-font-body);
            line-height: var(--skynet-line-body);
            transition: background-color 0.15s ease;
        }

        .skynet-action-row:first-child { border-top: 0; }

        .skynet-action-row:nth-child(odd) {
            background: rgba(255,255,255,0.015);
        }

        .skynet-action-row:hover {
            background: rgba(121,198,231,0.055);
        }

        .skynet-action-time {
            min-width: 0;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .skynet-action-summary,
        .skynet-action-detail {
            min-width: 0;
            overflow-wrap: anywhere;
            white-space: normal;
        }

        .skynet-action-time {
            color: var(--skynet-muted) !important;
            font-variant-numeric: tabular-nums;
        }

        .skynet-action-result {
            justify-self: start;
            min-width: 54px;
            padding: 2px 8px !important;
            border: 1px solid transparent !important;
            border-radius: 10px;
            font-size: var(--skynet-font-caption);
            font-weight: 600;
            line-height: 15px;
            text-align: center;
        }

        #FormTitle .skynet-action-result.success {
            color: var(--skynet-success) !important;
            border-color: rgba(105,190,137,0.42) !important;
            background: rgba(65,126,87,0.18) !important;
        }

        #FormTitle .skynet-action-result.degraded {
            color: var(--skynet-warning) !important;
            border-color: rgba(210,177,80,0.42) !important;
            background: rgba(145,111,31,0.17) !important;
        }

        #FormTitle .skynet-action-result.failed {
            color: var(--skynet-error) !important;
            border-color: rgba(205,103,113,0.42) !important;
            background: rgba(135,58,68,0.17) !important;
        }

        #FormTitle .skynet-action-summary {
            color: var(--skynet-text) !important;
            font-weight: 600;
        }

        #FormTitle .skynet-action-detail {
            color: var(--skynet-muted) !important;
        }

        .skynet-action-list {
            max-height: 220px;
            overflow-y: auto;
        }

        #skynetRuleActivity .skynet-feed-empty {
            padding: 16px 12px;
            color: var(--skynet-muted) !important;
            text-align: center;
        }

        .skynet-iot-add {
            display: flex;
            align-items: center;
            gap: 7px;
        }

        .skynet-iot-add .skynet-update-button {
            min-width: 62px;
        }

        .skynet-iot-tag-main,
        .skynet-iot-tag-meta {
            display: inline-block;
        }

        .skynet-iot-tag-meta {
            color: var(--skynet-muted);
            font-size: var(--skynet-font-caption);
            line-height: var(--skynet-line-caption);
        }

        .skynet-settings-actions {
            display: flex;
            align-items: center;
            justify-content: flex-end;
            gap: 8px;
            padding: 8px 10px;
            border-top: 1px solid var(--skynet-border-soft);
            background: rgba(0,0,0,0.09);
        }

        .skynet-settings-result {
            flex: 1;
            color: var(--skynet-muted);
            font-size: var(--skynet-font-body);
            line-height: 15px;
        }

        .skynet-settings-actions .skynet-country-status {
            flex:1;
            min-width:0;
        }

        .skynet-settings-actions[data-active-section="countries"] {
            flex-wrap: wrap;
        }

        .skynet-settings-actions[data-active-section="rules"] {
            display: none;
        }

        .skynet-settings-actions[data-active-section="countries"]
        #skynetCountryStatus:not(:empty) {
            flex: 1 0 100%;
            order: -1;
            line-height: var(--skynet-line-body);
        }

        .skynet-settings-action-hidden {
            display:none !important;
        }

        .skynet-settings-result.error {
            color: var(--skynet-error);
        }

        /* Details. */
        .skynet-detail {
            display: none;
            width: 100% !important;
            max-width: 760px !important;
            margin: 8px 0 10px 0;
            background: var(--skynet-surface);
            border: 1px solid var(--skynet-border-medium);
            border-radius: 6px;
            box-sizing: border-box;
            overflow: hidden;
            box-shadow:
                0 2px 6px rgba(0,0,0,0.18),
                inset 0 1px 0 rgba(255,255,255,0.03);
        }

        .skynet-detail.visible {
            display: block;
        }

        .skynet-detail-head {
            display: flex;
            align-items: center;
            justify-content: space-between;
            min-height: 38px;
            box-sizing: border-box;
            background: linear-gradient(180deg, #66767b 0%, #536267 100%);
            border-bottom: 1px solid #75858a;
            color: #fff;
            padding: 6px 10px;
            font-size: 13px;
            font-weight: bold;
            text-shadow: 0 1px 1px rgba(0,0,0,0.24);
        }

        .skynet-detail-close {
            min-width: 58px;
            height: 28px;
            margin: 0 !important;
        }

        .skynet-detail-identity {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 10px;
            margin: 10px;
            padding: 9px 11px;
            background: var(--skynet-surface-2);
            border: 1px solid var(--skynet-border-medium);
            border-radius: 5px;
            box-sizing: border-box;
        }

        .skynet-detail-identity-text {
            min-width: 0;
        }

        .skynet-detail-identity-label {
            color: var(--skynet-muted-2);
            font-size: var(--skynet-font-caption);
            line-height: var(--skynet-line-caption);
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 0.35px;
        }

        .skynet-detail-identity-value {
            margin-top: 2px;
            color: var(--skynet-title);
            font-size: 17px;
            line-height: 21px;
            font-weight: bold;
            letter-spacing: 0.15px;
            word-break: break-word;
        }

        .skynet-detail-copy-primary {
            flex: 0 0 auto;
        }

        .skynet-detail-body {
            padding: 0 10px 10px 10px;
        }

        .skynet-detail-grid {
            width: 100%;
            border-collapse: collapse;
            table-layout: fixed;
            background: var(--skynet-surface);
        }

        .skynet-detail-grid td {
            padding: 7px 8px;
            border-bottom: 1px solid var(--skynet-border-faint);
            color: var(--skynet-body);
            vertical-align: middle;
        }

        .skynet-detail-grid tr:last-child td {
            border-bottom: 0;
        }

        .skynet-detail-grid td:first-child {
            width: 150px;
            color: var(--skynet-muted-2);
            font-size: var(--skynet-font-body);
            line-height: var(--skynet-line-body);
            font-weight: bold;
            letter-spacing: 0.2px;
            text-transform: uppercase;
            white-space: nowrap;
        }

        .skynet-detail-grid td + td {
            border-left: 1px solid var(--skynet-border-faint);
            color: var(--skynet-body);
        }

        .skynet-detail-grid td:nth-child(2) {
            text-align: left !important;
        }

        .skynet-detail-grid td:nth-child(2) .skynet-detail-value-wrap {
            min-height: 20px;
        }

        .skynet-detail-value-wrap {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 8px;
            min-width: 0;
        }

        .skynet-detail-value {
            min-width: 0;
            color: var(--skynet-title);
            font-weight: bold;
            word-break: break-word;
        }

        .skynet-detail-copy,
        .skynet-detail-domain-toggle {
            flex: 0 0 auto;
            min-width: 48px;
            height: 28px;
            padding: 0 7px !important;
            font-size: var(--skynet-font-body) !important;
        }

        .skynet-detail-copy.copied {
            border-color: #6dbb8d !important;
            background: linear-gradient(#6fae87, #4e8063) !important;
        }

        .skynet-domain-list {
            white-space: pre-line;
        }

        #FormTitle .skynet-domain-list.collapsed {
            color: var(--skynet-muted-2) !important;
        }

        #FormTitle .skynet-detail-value-actions {
            display: flex;
            flex-shrink: 0;
            gap: 6px;
            padding: 0 !important;
            border: 0 !important;
            background: transparent !important;
        }

        .skynet-detail-actions {
            display: flex;
            justify-content: flex-end;
            gap: 6px;
            margin-top: 10px;
        }
        .skynet-detail-lookup {
            min-width: 108px;
            height: 28px;
            padding: 0 9px !important;
            border-color: #668a9e !important;
            background: #405b67 !important;
            color: #e4f3f8 !important;
            font-size: var(--skynet-font-body) !important;
            font-weight: bold;
            letter-spacing: 0.1px;
        }
        .skynet-detail-lookup:hover {
            background: #4b6a77 !important;
            border-color: #7eacbf !important;
        }

        .skynet-context-link {
            cursor: pointer;
            color: var(--skynet-link) !important;
            font-weight: bold !important;
            text-decoration: none !important;
        }

        .skynet-context-link:hover {
            text-decoration: underline !important;
        }

        .skynet-context-selected {
            text-decoration: underline !important;
        }


        /* Statistics. */
        .skynet-section {
            width: 100% !important;
            max-width: 760px !important;
            margin-top: 8px;
        }

        .skynet-section > table {
            width: 100% !important;
            max-width: 760px !important;
            table-layout: fixed !important;
            border-collapse: collapse !important;
        }

        .skynet-section-head,
        .skynet-section-head tr,
        .skynet-section-head td {
            width: 100% !important;
            box-sizing: border-box;
        }

        .skynet-section-head td:first-child {
            width: auto !important;
            text-align: left;
        }

        .skynet-section-head td:last-child {
            width: 34px !important;
            text-align: center !important;
            padding-left: 0 !important;
            padding-right: 0 !important;
        }

        .skynet-section-body-row > td {
            width: 100% !important;
            box-sizing: border-box !important;
        }

        .skynet-controls-table {
            width: 100% !important;
            table-layout: fixed !important;
            border-collapse: collapse !important;
        }

        .skynet-controls-table td {
            vertical-align: middle;
        }

        .skynet-controls-table .skynet-control-cell {
            width: 50% !important;
            box-sizing: border-box !important;
        }

        .skynet-controls-table .skynet-control-cell + .skynet-control-cell {
            border-left: 1px solid var(--skynet-border-soft) !important;
        }

        .StatsTable.skynet-modern-table th + th,
        .StatsTable.skynet-modern-table td + td {
            border-left: 1px solid var(--skynet-border-faint) !important;
        }

        .skynet-modern-table thead th {
            border-right: 1px solid var(--skynet-border-soft) !important;
        }

        .skynet-modern-table thead th:last-child {
            border-right: 0 !important;
        }

        .skynet-modern-table tr:not(:last-child) td {
            box-shadow: inset 0 -1px 0 rgba(115, 137, 145, 0.14);
        }

        .skynet-modern-table th:first-child,
        .skynet-modern-table td:first-child {
            border-left: 0 !important;
        }

        .skynet-modern-table th,
        .skynet-modern-table td {
            box-sizing: border-box !important;
            font-family: inherit !important;
            line-height: var(--skynet-line-body) !important;
        }

        .skynet-section-head {
            background: linear-gradient(180deg,#405158 0%,#35454b 100%) !important;
            color: #fff !important;
            border: 1px solid #607780 !important;
            border-radius: 6px 6px 0 0;
            height: 36px;
            box-sizing: border-box;
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.055),
                        0 1px 2px rgba(0,0,0,0.12);
            transition: background 140ms ease,border-color 140ms ease;
        }

        .skynet-section-head:hover,
        .skynet-section-head:focus-visible {
            background: linear-gradient(180deg,#485d65 0%,#3b4e55 100%) !important;
            border-color: #748e98 !important;
            outline: none;
        }

        .skynet-section-head.collapsed {
            border-radius: 6px;
        }

        .skynet-section-head td {
            color: var(--skynet-title) !important;
            font-size: 13px !important;
            font-weight: bold !important;
            line-height: 18px !important;
            padding: 7px 10px !important;
        }

        .skynet-section-head td:first-child {
            letter-spacing: 0.1px;
        }

        .skynet-section-head td:last-child {
            text-align: right;
            width: 30px;
            color: #dce4e7 !important;
        }

        .skynet-section-toggle {
            font-size: 15px;
            line-height: 12px;
            opacity: 0.9;
            transition: color 140ms ease,opacity 140ms ease;
        }

        .skynet-empty-badge {
            display: inline-block;
            margin-left: 8px;
            padding: 1px 6px;
            border: 1px solid var(--skynet-border);
            border-radius: 8px;
            color: var(--skynet-muted);
            font-size: var(--skynet-font-caption);
            line-height: var(--skynet-line-caption);
            font-weight: normal;
            letter-spacing: 0.2px;
            vertical-align: 1px;
        }

        .skynet-controls {
            background: var(--skynet-panel) !important;
            border-top-color: var(--skynet-border-medium) !important;
            border-left: 1px solid var(--skynet-border) !important;
            border-right: 1px solid var(--skynet-border) !important;
            border-bottom: 1px solid var(--skynet-border) !important;
            padding: 7px 10px !important;
        }

        .skynet-control-label {
            color: var(--skynet-body) !important;
            font-size: var(--skynet-font-caption);
            line-height: var(--skynet-line-caption);
            font-weight: bold;
            letter-spacing: 0.25px;
            margin-right: 5px;
            text-transform: uppercase;
        }
        .skynet-chart-shell {
            position: relative;
            width: 100%;
            height: 360px;
            overflow: hidden;
            background:
                radial-gradient(circle at 50% 0, rgba(53, 216, 255, 0.07), transparent 58%),
                #11191c;
            border: 1px solid #43565d;
            border-radius: 0 0 7px 7px;
            box-sizing: border-box;
            padding: 8px;
            box-shadow: inset 0 0 28px rgba(57, 239, 157, 0.035);
        }

        .skynet-chart-shell.skynet-activity-shell {
            height: 285px;
            overflow: hidden;
            background:
                radial-gradient(circle at 50% 0, rgba(53, 216, 255, 0.08), transparent 58%),
                #11191c;
            box-shadow: inset 0 0 28px rgba(57, 239, 157, 0.04);
        }

        .skynet-chart-shell::before {
            content: "";
            position: absolute;
            inset: 0;
            z-index: 0;
            pointer-events: none;
            background: repeating-linear-gradient(
                0deg,
                rgba(255, 255, 255, 0.018) 0,
                rgba(255, 255, 255, 0.018) 1px,
                transparent 1px,
                transparent 4px
            );
        }


        .skynet-chart-shell canvas {
            display: block;
            position: relative;
            z-index: 1;
            width: 100% !important;
            height: 100% !important;
            max-width: 100%;
        }

        .skynet-table-shell {
            background: var(--skynet-panel);
            border-left: 1px solid var(--skynet-border);
            border-right: 1px solid var(--skynet-border);
            border-bottom: 1px solid var(--skynet-border);
            border-radius: 0 0 5px 5px;
            padding: 0;
            overflow: hidden;
        }

        .StatsTable.skynet-modern-table {
            width: 100% !important;
            max-width: 760px !important;
            table-layout: fixed !important;
            border: 0 !important;
            background: var(--skynet-panel) !important;
        }

        .StatsTable.skynet-modern-table td,
        .StatsTable.skynet-modern-table th {
            overflow-wrap: anywhere;
        }

        .StatsTable.skynet-modern-table th {
            background: var(--skynet-bg) !important;
            color: var(--skynet-heading) !important;
            border: 0 !important;
            border-bottom: 1px solid #52656c !important;
            font-size: var(--skynet-font-caption) !important;
            line-height: var(--skynet-line-caption) !important;
            padding: 7px 8px !important;
            text-align: left !important;
            text-transform: uppercase;
            vertical-align: middle !important;
        }

        .StatsTable.skynet-modern-table td {
            border: 0 !important;
            border-bottom: 1px solid #4b5b61 !important;
            padding: 7px 8px !important;
            color: var(--skynet-text) !important;
            font-size: var(--skynet-font-body) !important;
            vertical-align: middle !important;
            text-align: left !important;
        }

        .StatsTable.skynet-modern-table th:nth-child(1),
        .StatsTable.skynet-modern-table td:nth-child(1) {
            text-align: left !important;
        }

        .StatsTable.skynet-modern-table th:nth-child(2),
        .StatsTable.skynet-modern-table td:nth-child(2) {
            text-align: left !important;
        }

        .StatsTable.skynet-modern-table th:nth-child(3),
        .StatsTable.skynet-modern-table td:nth-child(3) {
            text-align: center !important;
        }

        .StatsTable.skynet-modern-table th:nth-child(4),
        .StatsTable.skynet-modern-table td:nth-child(4) {
            text-align: center !important;
        }

        .StatsTable.skynet-modern-table th:nth-child(5),
        .StatsTable.skynet-modern-table td:nth-child(5) {
            text-align: left !important;
        }

        .StatsTable.skynet-modern-table .skynet-table-details,
        .StatsTable.skynet-modern-table .skynet-table-country {
            text-align: center !important;
        }

        .StatsTable.skynet-modern-table .skynet-table-country {
            overflow-wrap: normal;
            white-space: nowrap;
        }

        .StatsTable.skynet-modern-table th.skynet-table-domains,
        .StatsTable.skynet-modern-table td.skynet-table-domains {
            text-align: left !important;
        }

        #FormTitle .skynet-domain-preview {
            display: block;
            color: var(--skynet-text) !important;
            line-height: var(--skynet-line-body);
            word-break: break-word;
        }

        #FormTitle .skynet-domain-more {
            display: inline-block;
            margin-top: 3px;
            color: var(--skynet-accent-muted) !important;
            font-size: var(--skynet-font-caption);
            font-weight: bold;
            line-height: var(--skynet-line-caption);
        }

        .StatsTable.skynet-modern-table tr:nth-child(even) td {
            background: var(--skynet-panel-alt) !important;
        }

        .StatsTable.skynet-modern-table tr:hover td {
            background: #42545b !important;
        }

        .StatsTable.skynet-modern-table tr:last-child td {
            border-bottom: 0 !important;
        }

        #FormTitle .skynet-ip-value {
            color: var(--skynet-link) !important;
            font-weight: bold;
            white-space: nowrap;
        }

        #FormTitle .StatsTable.skynet-modern-table td.skynet-context-link {
            color: var(--skynet-link) !important;
        }

        .skynet-external-link {
            color: var(--skynet-link) !important;
            font-weight: bold !important;
        }

        .skynet-nodata {
            min-height: 180px;
            box-sizing: border-box;
            padding: 24px;
            display: flex !important;
            align-items: center;
            justify-content: center;
            color: var(--skynet-muted-2) !important;
            font-size: 16px;
            line-height: 22px;
            font-weight: bold;
            text-align: center;
            background: var(--skynet-bg);
        }

        .skynet-table-nodata {
            min-height: 150px;
            height: 150px !important;
        }

        .StatsTable td.skynet-nodata {
            height:180px !important;
            min-height:0;
            padding:24px !important;
            font-size:16px !important;
            line-height:22px !important;
            font-family:Arial !important;
            color:#cfd7da !important;
            background:var(--skynet-bg) !important;
        }

        /* Responsive. */
        @media (max-width: 900px) {
            .skynet-chart-shell {
                height: 320px;
            }

            .skynet-chart-shell.skynet-activity-shell {
                height: 270px;
            }
        }

        @media (max-width: 760px) {
            .skynet-tabs {
                flex-wrap: wrap;
            }

            .skynet-tab {
                flex: 1 1 calc(25% - 3px);
                min-height: 36px;
            }

            .skynet-hero {
                padding:42px 10px 12px 10px;
            }

            .skynet-hero-title {
                font-size:20px;
                letter-spacing:3px;
            }

            .skynet-project-link {
                position:static;
                display:inline-block;
                margin-top:8px;
            }

            .skynet-update-bar {
                align-items: stretch;
                grid-template-columns:1fr;
            }

            .skynet-update-button {
                width: 100%;
            }

            .skynet-update-control {
                width:100%;
            }

            .skynet-meta-item {
                flex:0 1 auto;
            }

            .skynet-meta {
                flex-wrap:wrap;
            }

            .skynet-meta-value {
                white-space:normal;
            }

            .skynet-update-info {
                align-items:flex-start;
                flex-direction:column;
                gap:5px;
            }

            .skynet-update-result {
                padding-left:0;
                border-left:0;
                white-space:normal;
            }

            .skynet-settings-actions {
                align-items: stretch;
                flex-direction: column;
            }

            .skynet-iot-add {
                align-items: stretch;
                flex-direction: column;
            }

            .skynet-settings-table select,
            .skynet-settings-actions .skynet-update-button {
                width: 100%;
            }

            .skynet-country-row th,
            .skynet-country-row td {
                display: block !important;
                box-sizing: border-box;
                width: 100% !important;
            }

            .skynet-country-row th {
                border-right: 0;
                border-bottom: 1px solid var(--skynet-border-soft);
            }

            .skynet-malware-controls {
                align-items: stretch;
                flex-direction: column;
            }

            .skynet-malware-update {
                width: 100%;
            }

            .skynet-feed-header {
                display: none;
            }

            .skynet-feed-intro {
                padding: 9px 10px;
            }

            .skynet-feed-row {
                grid-template-columns: minmax(0, 1fr) auto;
                gap: 4px 10px;
                padding: 9px 10px;
            }

            .skynet-feed-source {
                grid-column: 1;
                grid-row: 1;
            }

            .skynet-feed-entries,
            .skynet-feed-success {
                grid-column: 1;
                text-align: left;
            }

            .skynet-feed-entries::before,
            .skynet-feed-success::before {
                color: var(--skynet-muted);
                font-size: var(--skynet-font-caption);
                text-transform: uppercase;
            }

            .skynet-feed-entries::before {
                content: "Entries  ";
            }

            .skynet-feed-success::before {
                content: "Last success  ";
            }

            .skynet-feed-state {
                grid-column: 2;
                grid-row: 2 / 4;
                align-self: center;
            }

            .skynet-feed-toggle {
                grid-column: 2;
                grid-row: 1;
                justify-self: end;
                margin: 0;
            }

            .skynet-country-health-header,
            .skynet-rule-header {
                display: none;
            }

            .skynet-country-health-row {
                grid-template-columns: minmax(0, 1fr) auto 28px;
                gap: 4px 10px;
            }

            .skynet-country-health-count {
                grid-column: 1;
            }

            .skynet-country-health-date {
                grid-column: 1;
                white-space: normal;
            }

            .skynet-country-health-state {
                grid-column: 2;
                grid-row: 1 / 4;
                align-self: center;
            }

            .skynet-country-health-remove {
                grid-column: 3;
                grid-row: 1 / 4;
                align-self: center;
            }

            .skynet-country-health-count::before {
                content: "Ranges ";
                color: var(--skynet-muted);
            }

            .skynet-country-health-date::before {
                content: "Last success  ";
                color: var(--skynet-muted);
                font-size: var(--skynet-font-caption);
                text-transform: uppercase;
            }

            .skynet-country-health-count {
                text-align: left;
            }

            .skynet-rules-toolbar,
            .skynet-rules-filterbar,
            .skynet-rules-actions,
            .skynet-rule-overview {
                align-items: stretch;
                flex-direction: column;
            }

            .skynet-rule-health {
                align-items: flex-start;
            }

			.skynet-rule-freshness {
				flex-wrap: wrap;
				white-space: normal;
			}

			.skynet-rule-age {
				white-space: normal;
			}

            .skynet-rule-field,
            .skynet-rule-field-entries {
                flex: 0 0 auto;
                min-height: 0;
                width: 100%;
            }

            .skynet-rules-search {
                margin-left: 0;
            }

            .skynet-rule-row {
                grid-template-columns: minmax(0, 1fr) auto;
                gap: 3px 10px;
            }

            .skynet-rule-type,
            .skynet-rule-entry,
            .skynet-rule-comment {
                grid-column: 1;
            }

            .skynet-rule-count {
                grid-column: 2;
                grid-row: 1;
            }

            .skynet-rule-entry::before,
            .skynet-rule-comment::before,
            .skynet-rule-count::before {
                color: var(--skynet-muted);
                font-size: var(--skynet-font-caption);
                text-transform: uppercase;
            }

            .skynet-rule-entry::before {
                content: "Entry  ";
            }

            .skynet-rule-comment::before {
				content: "Details  ";
            }

            .skynet-rule-comment.freshness::before {
                content: "Freshness  ";
            }

            .skynet-rule-count::before {
                content: "Count  ";
            }

            .skynet-rule-remove {
                grid-column: 2;
                grid-row: 2 / 4;
                align-self: center;
            }

            .skynet-action-header {
                display: none;
            }

            .skynet-action-row {
                grid-template-columns: minmax(0, 1fr) auto;
                gap: 3px 10px;
            }

            .skynet-action-time,
            .skynet-action-summary,
            .skynet-action-detail {
                grid-column: 1;
                overflow-wrap: anywhere;
                white-space: normal;
            }

            .skynet-action-result {
                grid-column: 2;
                grid-row: 1 / 4;
                align-self: center;
            }

            .skynet-feed-actions {
                align-items: stretch;
                flex-direction: column;
            }

            .skynet-feed-actions .skynet-update-button {
                width: 100%;
            }

            .skynet-table-shell {
                overflow-x: auto;
                -webkit-overflow-scrolling: touch;
            }

            .StatsTable.skynet-modern-table {
                min-width: 560px;
            }

            .skynet-chart-shell {
                height: 280px;
            }

            .skynet-chart-shell.skynet-activity-shell {
                height: 245px;
            }

        }

        @media (max-width: 600px) {
            .skynet-settings-table tr:not(.skynet-settings-group) > th,
            .skynet-settings-table tr:not(.skynet-settings-group) > td {
                display: block !important;
                box-sizing: border-box;
                width: 100% !important;
            }

            .skynet-settings-table tr:not(.skynet-settings-group) > th {
                border-right: 0 !important;
                border-bottom: 1px solid var(--skynet-border-soft) !important;
            }

            .skynet-controls-table .skynet-control-cell {
                display: block;
                width: 100% !important;
            }

            .skynet-controls-table .skynet-control-cell + .skynet-control-cell {
                border-top: 1px solid var(--skynet-border-soft) !important;
                border-left: 0 !important;
            }
        }

        @media (max-width: 520px) {
            .skynet-kpis,
            .skynet-kpis tbody,
            .skynet-kpis tr {
                display: block;
            }

            .skynet-kpis tr {
                display: grid;
                grid-template-columns: repeat(2, minmax(0, 1fr));
                gap: 6px;
            }

            .skynet-kpi {
                display: block;
                width: auto !important;
            }

            .skynet-detail-grid td:first-child {
                width: 105px;
                white-space: normal;
            }

            .skynet-detail-actions {
                flex-wrap: wrap;
            }
        }

    </style>
    <script src="/js/chart.min.js"></script>
    <script src="/ext/skynet/stats.js"></script>
    <script src="/ext/skynet/settings.js"></script>
    <script src="/js/jquery.js"></script>
    <script src="/js/httpApi.js"></script>
    <script src="/state.js"></script>
    <script src="/client_function.js"></script>
    <script src="/general.js"></script>
    <script src="/popup.js"></script>
    <script src="/help.js"></script>
    <script src="/detect.js"></script>
    <script src="/validator.js"></script>
    <script>
        var custom_settings = <% get_custom_settings(); %>;

        if (!custom_settings || typeof custom_settings !== "object" || Array.isArray(custom_settings)) {
            custom_settings = {};
        }

        /*
         * Skynet WebUI client layer.
         * Integrates Skynet statistics with the native Asuswrt-Merlin page.
         */


        const SkynetUI = {
            /*
             * Runtime state. "Original" values are canonical snapshots from
             * settings.js; their matching selections contain unsaved edits.
             */
            charts: Object.create(null),
            chartData: Object.create(null),
            theme: Object.create(null),
            refreshInProgress: false,
            chartResizeBound: false,
            countryNames: Object.create(null),
            countryDisplayNames: null,
            countrySelection: [],
            countryOriginal: "",
            ruleEntries: [],
            ruleFilter: "all",
            ruleConfirm: "",
            settingsOriginal: "",
            feedExclusions: [],
            feedOriginal: "",
            iotSelection: [],
            iotPortSelection: [],
            iotOriginal: "",
            iotOptionsOriginal: "",
            settingsSection: "updates",
            reloadResult: "",

            /*
             * Static definitions. A chart "setting" names the backend switch
             * required for that chart to exist, not merely its default state.
             */
            chartColors: [
                "#35D8FF", "#39EF9D", "#FFCF5C", "#FF5F6D", "#C875FF",
                "#2FE1C4", "#FF8C42", "#65A5FF", "#E96BFF", "#8CFF66"
            ],
            countryCodes: "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW".split(" "),
            chartDefinitions: {
                ActivityToday: {
                    title: "Block Activity Today",
                    multiLabel: false,
                    activity: true
                },
                TCConnHits: {
                    title: "Top 10 Blocked Devices (Outbound)",
                    multiLabel: false,
                    legendLabel: "IP ADDRESS"
                },
                TOConnHits: {
                    title: "Top 10 Blocks (Outbound)",
                    multiLabel: true,
                    legendLabel: "IP ADDRESS"
                },
                TIConnHits: {
                    title: "Top 10 Blocks (Inbound)",
                    multiLabel: true,
                    legendLabel: "IP ADDRESS"
                },
                THConnHits: {
                    title: "Top 10 HTTP(s) Blocks (Outbound)",
                    multiLabel: true,
                    legendLabel: "IP ADDRESS"
                },
                TInvConnHits: {
                    title: "Top 10 Blocks (Invalid)",
                    multiLabel: true,
                    legendLabel: "IP ADDRESS",
                    setting: "loginvalid"
                },
                TIOTConnHits: {
                    title: "Top 10 IoT Blocks (Outbound)",
                    multiLabel: true,
                    legendLabel: "IP ADDRESS",
                    setting: "iotblocked"
                },
                SPortHits: {
                    title: "Top 10 Source Ports (Inbound)",
                    multiLabel: false,
                    legendLabel: "PORT NUMBER"
                },
                InPortHits: {
                    title: "Top 10 Targeted Ports (Inbound)",
                    multiLabel: false,
                    legendLabel: "PORT NUMBER"
                }
            },
            tableDefinitions: {
                HTTPConn: "Last 10 Unique HTTP(s) Blocks (Outbound)",
                OutConn: "Last 10 Unique Connections Blocked (Outbound)",
                InConn: "Last 10 Unique Connections Blocked (Inbound)"
            },
            selectors: {
                statsContent: "skynetDynamicContent",
                updateButton: "skynetUpdateStats",
                updateResult: "skynetUpdateResult",
                settingsButton: "skynetApplySettings",
                settingsReloadButton: "skynetReloadSettings",
                settingsDefaultsButton: "skynetRestoreDefaults",
                malwareButton: "skynetUpdateMalware",
                malwareStatus: "skynetMalwareStatus",
                feedList: "skynetFeedList",
                feedButton: "skynetApplyFeeds",
                feedStatus: "skynetFeedStatus",
                countryPicker: "skynetCountryPicker",
                countryButton: "skynetApplyCountries",
                countryRefresh: "skynetRefreshCountries",
                countryClear: "skynetClearCountries",
                countryResult: "skynetCountryStatus",
                countryHealth: "skynetCountryHealthList",
                ruleAction: "skynetRuleAction",
                ruleMode: "skynetRuleMode",
                ruleInput: "skynetRuleInput",
                ruleComment: "skynetRuleComment",
                ruleAdd: "skynetAddRuleEntry",
                ruleTags: "skynetRuleTags",
                ruleFilter: "skynetRuleFilter",
                ruleSearch: "skynetRuleSearch",
                ruleList: "skynetRuleList",
                ruleHealth: "skynetRuleHealth",
                ruleActivity: "skynetRuleActivity",
                ruleRefresh: "skynetRefreshRules",
                ruleButton: "skynetApplyRule",
                ruleResult: "skynetRuleStatus",
                iotPicker: "skynetIotPicker",
                iotList: "skynetIotList",
                iotManual: "skynetIotManual",
                iotManualButton: "skynetAddIotManual",
                iotPortMode: "skynetIotPortMode",
                iotPortInput: "skynetIotPortInput",
                iotPortButton: "skynetAddIotPort",
                iotPortList: "skynetIotPortList",
                iotButton: "skynetApplyIot",
                iotClear: "skynetClearIot",
                iotResult: "skynetIotStatus",
                settingsResult: "skynetSettingsResult",
                overviewTab: "skynetOverviewTab",
                overviewView: "skynetOverviewView",
                settingsView: "skynetSettingsView"
            },
            actionDefinitions: {
                stats: {
                    button: "updateButton",
                    result: "updateResult",
                    label: "Refresh Stats",
                    success: "Statistics refreshed successfully.",
                    timeout: "Statistics refresh did not complete.",
                    loadError: "Unable to load refreshed data."
                },
                settings: {
                    button: "settingsButton",
                    result: "settingsResult",
                    label: "Apply Settings",
                    success: "Settings applied successfully.",
                    failure: "Unable to apply settings.",
                    timeout: "Settings update did not complete.",
                    loadError: "Unable to load current settings.",
                    source: "settings",
                    requireSuccess: true
                },
                reload: {
                    button: "settingsReloadButton",
                    result: "settingsResult",
                    label: "Reload Data",
                    success: "Current data reloaded.",
                    timeout: "Data reload did not complete.",
                    loadError: "Unable to load current settings.",
                    source: "settings"
                },
                malware: {
                    button: "malwareButton",
                    result: "settingsResult",
                    label: "Update Now",
                    success: "Malware lists updated successfully.",
                    failure: "Unable to update malware lists.",
                    timeout: "Malware list update did not complete.",
                    loadError: "Unable to load current settings.",
                    source: "settings",
                    requireSuccess: true,
                    accepted: ["success", "degraded"]
                },
                feeds: {
                    button: "feedButton",
                    result: "feedStatus",
                    label: "Apply Sources",
                    success: "Threat feed selection applied successfully.",
                    failure: "Unable to apply threat feed selection.",
                    timeout: "Threat feed update did not complete.",
                    loadError: "Unable to load current source details.",
                    source: "settings",
                    requireSuccess: true,
                    accepted: ["success", "degraded"]
                },
                countries: {
                    button: "countryButton",
                    result: "countryResult",
                    label: "Apply Countries",
                    success: "Country blocking updated successfully.",
                    failure: "Unable to update country blocking.",
                    timeout: "Country blocking update did not complete.",
                    loadError: "Unable to load current country settings.",
                    source: "settings",
                    requireSuccess: true,
                    accepted: ["success", "degraded"]
                },
                countryRefresh: {
                    button: "countryRefresh",
                    result: "countryResult",
                    label: "Refresh Sources",
                    success: "Country sources refreshed successfully.",
                    failure: "Unable to refresh country sources.",
                    timeout: "Country source refresh did not complete.",
                    loadError: "Unable to load current country source details.",
                    source: "settings",
                    requireSuccess: true,
                    accepted: ["success", "degraded"]
                },
                rules: {
                    button: "ruleButton",
                    result: "ruleResult",
                    label: "Apply Rule",
                    success: "Rules updated successfully.",
                    failure: "Unable to update rules.",
                    timeout: "Rules update did not complete.",
                    loadError: "Unable to load current rules.",
                    source: "settings",
                    requireSuccess: true,
                    accepted: ["success", "warning"]
                },
                ruleRefresh: {
                    button: "ruleRefresh",
                    result: "ruleResult",
                    label: "Refresh Dynamic Rules",
                    success: "Dynamic rules refreshed successfully.",
                    failure: "Unable to refresh dynamic rules.",
                    timeout: "Rule refresh did not complete.",
                    loadError: "Unable to load current rule health.",
                    source: "settings",
                    requireSuccess: true,
                    accepted: ["success", "degraded"]
                },
                iot: {
                    button: "iotButton",
                    result: "iotResult",
                    label: "Apply IoT",
                    success: "IoT isolation updated successfully.",
                    failure: "Unable to update IoT isolation.",
                    timeout: "IoT isolation update did not complete.",
                    loadError: "Unable to load current IoT settings.",
                    source: "settings",
                    requireSuccess: true
                }
            }
        };

        /* Shared utilities. */
        SkynetUI.getElement = function(id) {
            return document.getElementById(id);
        };

        SkynetUI.getCssVariable = function(name, fallback) {
            const value = window.getComputedStyle(document.documentElement)
                .getPropertyValue(name)
                .trim();

            return value || fallback;
        };

        SkynetUI.initializeTheme = function() {
            this.theme.text = this.getCssVariable("--text-regular-color", "#CCCCCC");
            this.theme.grid = this.getCssVariable("--border-color", "#3B4549");
        };

        SkynetUI.getChartTextColor = function() {
            return this.theme.text || this.getCssVariable("--text-regular-color", "#CCCCCC");
        };

        SkynetUI.getChartGridColor = function() {
            return this.theme.grid || this.getCssVariable("--border-color", "#3B4549");
        };

        SkynetUI.getChartColor = function(index) {
            return this.chartColors[index % this.chartColors.length];
        };

        SkynetUI.formatNumber = function(value) {
            const number = Number(value);

            return Number.isFinite(number)
                ? Math.round(number).toLocaleString()
                : "0";
        };

        SkynetUI.getCountryName = function(value) {
            const code = String(value || "").trim().toUpperCase();

            if (!code) {
                return "";
            }

            if (Object.prototype.hasOwnProperty.call(this.countryNames, code)) {
                return this.countryNames[code];
            }

            let name = code;

            /*
             * Convert compact country codes to localized display names when
             * supported by the browser, with the original code as fallback.
             */
            if (typeof Intl !== "undefined" &&
                typeof Intl.DisplayNames === "function") {
                try {
                    if (!this.countryDisplayNames) {
                        this.countryDisplayNames = new Intl.DisplayNames(["en-AU"], {
                            type: "region"
                        });
                    }
                    const displayName = this.countryDisplayNames.of(code);

                    if (displayName && displayName !== code) {
                        name = displayName;
                    }
                } catch (error) {
                    /* Retain the original country code. */
                }
            }

            this.countryNames[code] = name;
            return name;
        };
        SkynetUI.formatChartLabels = function(labels, dataType) {
            if (!Array.isArray(labels) || dataType !== "country") {
                return labels;
            }

            return labels.map(function(label) {
                return SkynetUI.getCountryName(label);
            });
        };


        SkynetUI.escapeHtml = function(value) {
            return String(value === undefined || value === null ? "" : value)
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#39;");
        };

        SkynetUI.getCookie = function(name) {
            const value = cookie.get(name);

            return value === null || value === undefined ? null : value;
        };

        SkynetUI.setCookie = function(name, value) {
            cookie.set(name, value, 31);
        };

        SkynetUI.getSelectValue = function(id, fallback) {
            const element = this.getElement(id);

            if (!element) {
                return fallback;
            }

            const value = Number(element.value);

            return Number.isFinite(value) ? value : fallback;
        };

        SkynetUI.loadChartData = function(chartName, multiLabel) {
            /*
             * stats.js follows Data<Name>/Label<Name> naming. Multi-label
             * charts expose raw IP rows plus pre-grouped country rows.
             */
            let data;
            let labels;

            if (multiLabel === "false") {
                data = window["Data" + chartName];
                labels = window["Label" + chartName];
            } else {
                const group = this.getElement(chartName + "_Group");
                const groupValue = group ? Number(group.value) : 0;

                if (groupValue === 0) {
                    data = window["Data" + chartName];
                    labels = window["Label" + chartName + "_IPs"];
                } else {
                    data = window["Data" + chartName + "_Sum"];
                    labels = window["Label" + chartName + "_Sorted"];
                }
            }

            if (!Array.isArray(data) || !Array.isArray(labels)) {
                this.chartData[chartName] = null;
                return null;
            }

            const cleanData = [];
            const cleanLabels = [];

            data.forEach(function(value, index) {
                const label = labels[index];

                if (label === undefined || label === null || label === "") {
                    return;
                }

                cleanLabels.push(String(label));
                cleanData.push(Number(value) || 0);
            });

            this.chartData[chartName] = cleanData.length
                ? { data: cleanData, labels: cleanLabels }
                : null;

            return this.chartData[chartName];
        };

        SkynetUI.canGroupByCountry = function(chartName) {
            const settings = window.SkynetSettings;
            const countries = window["Label" + chartName + "_Country"];

            if (settings && settings.lookupcountry === "disabled") {
                return false;
            }

            return Array.isArray(countries) && countries.some(function(country) {
                const value = String(country || "").trim();
                return value && value !== "*" && value !== "**";
            });
        };

        SkynetUI.getChartCountry = function(chartName, index) {
            const settings = window.SkynetSettings;

            if (settings && settings.lookupcountry === "disabled") {
                return "";
            }

            const countries = window["Label" + chartName + "_Country"];
            const country = Array.isArray(countries)
                ? String(countries[index] || "").trim()
                : "";

            return country === "*" || country === "**" ? "" : country;
        };

        SkynetUI.isChartEnabled = function(definition) {
            const settings = window.SkynetSettings;

            return !definition.setting ||
                (settings && settings[definition.setting] === "enabled");
        };

        SkynetUI.restoreSelect = function(id, minimum, maximum) {
            const element = this.getElement(id);

            if (!element) {
                return;
            }

            const saved = this.getCookie(id);

            if (saved === null || saved === "") {
                return;
            }

            const value = Number(saved);

            if (Number.isInteger(value) && value >= minimum && value <= maximum) {
                element.value = value;
            }
        };

        SkynetUI.storeSelect = function(element) {
            if (!element || !element.id) {
                return;
            }

            this.setCookie(element.id, Number(element.value));
        };

        /* Chart data and state. */
        SkynetUI.resizeCharts = function() {
            Object.keys(this.charts).forEach(function(chartName) {
                const chart = SkynetUI.charts[chartName];

                if (!chart || typeof chart.resize !== "function") {
                    return;
                }

                try {
                    chart.resize();
                } catch (error) {
                    /* Continue resizing the remaining charts if one chart fails. */
                }
            });
        };

        SkynetUI.scheduleChartResize = function() {
            const resize = function() {
                SkynetUI.resizeCharts();
            };

            if (typeof window.requestAnimationFrame === "function") {
                window.requestAnimationFrame(function() {
                    window.requestAnimationFrame(resize);
                });
            } else {
                window.setTimeout(resize, 50);
            }
        };

        SkynetUI.destroyChart = function(chartName) {
            const chart = this.charts[chartName];

            if (!chart) {
                return;
            }

            try {
                if (typeof chart.destroy === "function") {
                    chart.destroy();
                }
            } finally {
                delete this.charts[chartName];
            }
        };

        SkynetUI.showNoData = function(chartName) {
            /*
             * Empty sections collapse for the current render only. Their
             * saved cookie is left untouched so future data restores the
             * user's explicit open/closed preference.
             */
            const canvas = this.getElement("divChart" + chartName);

            if (!canvas) {
                return;
            }

            const parent = canvas.parentElement;

            if (!parent) {
                return;
            }

            const existing = parent.querySelector(".skynet-nodata");

            if (existing) {
                existing.remove();
            }

            canvas.style.display = "none";

            const message = document.createElement("div");
            message.className = "skynet-nodata";
            message.style.cssText = "position:absolute;inset:0;";
            message.textContent = "No data to display";

            parent.style.position = "relative";
            parent.appendChild(message);
            this.setChartEmpty(chartName, true);
        };

        SkynetUI.clearNoData = function(chartName) {
            const canvas = this.getElement("divChart" + chartName);

            if (!canvas) {
                return;
            }

            canvas.style.display = "";

            const parent = canvas.parentElement;

            if (!parent) {
                return;
            }

            const existing = parent.querySelector(".skynet-nodata");

            if (existing) {
                existing.remove();
            }

            this.setChartEmpty(chartName, false);
        };

        SkynetUI.setChartEmpty = function(chartName, empty) {
            const section = this.getElement("skynet_chart_" + chartName);

            if (!section) {
                return;
            }

            section.classList.toggle("skynet-section-empty", empty);

            const title = section.querySelector("td:first-child");
            const existing = title
                ? title.querySelector(".skynet-empty-badge")
                : null;

            if (empty && title && !existing) {
                const badge = document.createElement("span");
                badge.className = "skynet-empty-badge";
                badge.textContent = "No activity";
                title.appendChild(badge);
            } else if (!empty && existing) {
                existing.remove();
            }

            if (empty) {
                this.setSectionState(section, false, false);
            }
        };

        SkynetUI.getChartData = function(chartName, multiLabel) {
            const cached = this.chartData[chartName];

            if (cached) {
                return cached;
            }

            return this.loadChartData(chartName, multiLabel);
        };

        SkynetUI.getLegendLabel = function(chartName) {
            const definition = this.chartDefinitions[chartName];

            if (!definition) {
                return "VALUE";
            }

            if (definition.multiLabel) {
                const group = this.getElement(chartName + "_Group");
                return group && Number(group.value) === 1
                    ? "COUNTRY"
                    : "IP ADDRESS";
            }

            return definition.legendLabel || "VALUE";
        };

        SkynetUI.getChartConfiguration = function(chartName) {
            const layout = this.getSelectValue(chartName + "_Type", 0);

            if (layout === 2) {
                return {
                    type: "doughnut",
                    indexAxis: "x"
                };
            }

            return {
                type: "bar",
                indexAxis: layout === 0 ? "y" : "x"
            };
        };

        SkynetUI.getAxisLabel = function(chartName, axis, indexAxis) {
            if (chartName === "TCConnHits") {
                return indexAxis === "y"
                    ? (axis === "x" ? "Hits" : "IP Address / Device")
                    : (axis === "x" ? "IP Address / Device" : "Hits");
            }

            if (chartName === "InPortHits" || chartName === "SPortHits") {
                return indexAxis === "y"
                    ? (axis === "x" ? "Hits" : "Port Number")
                    : (axis === "x" ? "Port Number" : "Hits");
            }

            const group = this.getElement(chartName + "_Group");
            const groupValue = group ? Number(group.value) : 0;

            if (groupValue === 1) {
                return indexAxis === "y"
                    ? (axis === "x" ? "Hits" : "Country")
                    : (axis === "x" ? "Country" : "Hits");
            }

            return indexAxis === "y"
                ? (axis === "x" ? "Hits" : "IP Address")
                : (axis === "x" ? "IP Address" : "Hits");
        };

        /* Detail panel. */
        SkynetUI.closeDetails = function() {
            const panel = this.getElement("skynetDetail");

            if (!panel) {
                return;
            }

            panel.classList.remove("visible");
            panel.setAttribute("aria-hidden", "true");
        };

        SkynetUI.copyText = function(value, button) {
            const text = String(value === undefined || value === null ? "" : value);

            const showCopied = function() {
                if (!button) {
                    return;
                }

                const original = button.value;
                button.value = "Copied";
                button.classList.add("copied");

                window.setTimeout(function() {
                    button.value = original;
                    button.classList.remove("copied");
                }, 900);
            };

            if (navigator.clipboard &&
                typeof navigator.clipboard.writeText === "function") {
                navigator.clipboard.writeText(text)
                    .then(showCopied)
                    .catch(function() {
                        SkynetUI.copyTextFallback(text, button);
                    });
                return;
            }

            this.copyTextFallback(text, button);
        };

        SkynetUI.copyTextFallback = function(value, button) {
            const helper = document.createElement("textarea");

            helper.value = value;
            helper.setAttribute("readonly", "");
            helper.style.position = "fixed";
            helper.style.left = "-9999px";
            helper.style.top = "0";
            helper.style.opacity = "0";

            document.body.appendChild(helper);
            helper.focus();
            helper.select();

            try {
                document.execCommand("copy");

                if (button) {
                    const original = button.value;
                    button.value = "Copied";
                    button.classList.add("copied");

                    window.setTimeout(function() {
                        button.value = original;
                        button.classList.remove("copied");
                    }, 900);
                }
            } catch (error) {
                /* Clipboard support is optional in the router WebUI environment. */
            }

            helper.remove();
        };

        SkynetUI.openDetails = function(details) {
            const panel = this.getElement("skynetDetail");
            const title = this.getElement("skynetDetailTitle");
            const body = this.getElement("skynetDetailBody");

            if (!panel || !title || !body) {
                return;
            }

            title.textContent = details.title || "Skynet Details";

            const rows = [];
            const seenFields = Object.create(null);
            const copyLabels = {
                "IP Address": details.title === "Device Details",
                "MAC Address": details.title === "Device Details",
                "Port Number": false,
                "Device Name": false,
                "Associated Domains": true
            };

            details.fields.forEach(function(field) {
                if (field.value === undefined ||
                    field.value === null ||
                    field.value === "") {
                    return;
                }

                const fieldKey =
                    String(field.label).toLowerCase() + "\u0000" +
                    String(field.value);

                if (seenFields[fieldKey]) {
                    return;
                }

                seenFields[fieldKey] = true;

                const isDomains = field.label === "Associated Domains";
                const domainItems = isDomains
                    ? String(field.value).trim().split(/\s+/).filter(Boolean)
                    : [];
                const collapseDomains = domainItems.length > 1;
                const value = isDomains
                    ? (collapseDomains
                        ? domainItems.length + " domains"
                        : SkynetUI.escapeHtml(field.value).replace(/\s+/g, "\n"))
                    : SkynetUI.escapeHtml(field.value);

                const copyValue = SkynetUI.escapeHtml(field.value);
                const copyButton = copyLabels[field.label]
                    ? '<input type="button" class="button_gen skynet-detail-copy" ' +
                        'data-skynet-copy="' + copyValue + '" value="Copy" />'
                    : "";
                const domainToggle = collapseDomains
                    ? '<input type="button" class="button_gen skynet-detail-domain-toggle" ' +
                        'data-skynet-domains="' + copyValue + '" ' +
                        'data-skynet-domain-count="' + domainItems.length + '" ' +
                        'aria-expanded="false" value="Show" />'
                    : "";
                const valueActions = domainToggle || copyButton
                    ? '<span class="skynet-detail-value-actions">' +
                        domainToggle + copyButton + '</span>'
                    : "";

                rows.push(
                    '<tr>' +
                        '<td>' + SkynetUI.escapeHtml(field.label) + '</td>' +
                        '<td>' +
                            '<div class="skynet-detail-value-wrap">' +
                                '<span class="skynet-detail-value' +
                                    (isDomains ? ' skynet-domain-list' : '') +
                                    (collapseDomains ? ' collapsed' : '') +
                                    '">' + value + '</span>' +
                                valueActions +
                            '</div>' +
                        '</td>' +
                    '</tr>'
                );
            });

            let html = "";

            if (details.primary && details.primary.value !== undefined) {
                const primaryValue = String(details.primary.value);

                html +=
                    '<div class="skynet-detail-identity">' +
                        '<div class="skynet-detail-identity-text">' +
                            '<div class="skynet-detail-identity-label">' +
                                SkynetUI.escapeHtml(details.primary.label || "Selected") +
                            '</div>' +
                            '<div class="skynet-detail-identity-value">' +
                                SkynetUI.escapeHtml(primaryValue) +
                            '</div>' +
                        '</div>';

                if (details.primary.copy) {
                    html +=
                        '<input type="button" ' +
                        'class="button_gen skynet-detail-copy skynet-detail-copy-primary" ' +
                        'data-skynet-copy="' + SkynetUI.escapeHtml(primaryValue) + '"' +
                        ' value="Copy" />';
                }

                html += '</div>';
            }

            html +=
                '<table class="skynet-detail-grid">' +
                    rows.join("") +
                '</table>';

            if (details.actions && details.actions.length) {
                html += '<div class="skynet-detail-actions">';

                details.actions.forEach(function(action) {
                    html +=
                        '<input type="button" class="button_gen skynet-detail-action' +
                        (["AlienVault", "SpeedGuide"].indexOf(action.label) !== -1 ? ' skynet-detail-lookup' : '') + '" ' +
                        'data-skynet-detail-url="' +
                        SkynetUI.escapeHtml(action.url) +
                        '" value="' +
                        SkynetUI.escapeHtml(action.label) +
                        (["AlienVault", "SpeedGuide"].indexOf(action.label) !== -1 ? ' ↗' : '') +
                        '" /> ';
                });

                html += '</div>';
            }

            body.innerHTML = html;
            panel.classList.add("visible");
            panel.setAttribute("aria-hidden", "false");

            body.querySelectorAll("[data-skynet-copy]").forEach(function(button) {
                button.addEventListener("click", function() {
                    SkynetUI.copyText(
                        this.getAttribute("data-skynet-copy"),
                        this
                    );
                });
            });

            body.querySelectorAll("[data-skynet-domains]").forEach(function(button) {
                button.addEventListener("click", function() {
                    const list = this.parentNode.parentNode.querySelector(".skynet-domain-list");
                    const expanded = this.getAttribute("aria-expanded") === "true";
                    const count = Number(this.getAttribute("data-skynet-domain-count")) || 0;

                    if (!list) {
                        return;
                    }

                    if (expanded) {
                        list.textContent = count + " domains";
                        list.classList.add("collapsed");
                        this.value = "Show";
                    } else {
                        list.textContent = this.getAttribute("data-skynet-domains")
                            .trim().split(/\s+/).join("\n");
                        list.classList.remove("collapsed");
                        this.value = "Hide";
                    }

                    this.setAttribute("aria-expanded", expanded ? "false" : "true");
                });
            });

            body.querySelectorAll("[data-skynet-detail-url]").forEach(function(button) {
                button.addEventListener("click", function() {
                    const url = this.getAttribute("data-skynet-detail-url");

                    if (url) {
                        window.open(url, "_blank", "noopener");
                    }
                });
            });

            panel.scrollIntoView({
                behavior: "smooth",
                block: "nearest"
            });
        };

        SkynetUI.getDirection = function(chartName) {
            if (chartName === "TIConnHits" ||
                chartName === "InPortHits" ||
                chartName === "SPortHits") return "Inbound";
            if (chartName === "TOConnHits" ||
                chartName === "THConnHits" ||
                chartName === "TIOTConnHits" ||
                chartName === "TCConnHits") return "Outbound";
            return "";
        };

        SkynetUI.getStatisticName = function(chartName) {
            if (chartName === "TIConnHits" || chartName === "TOConnHits") {
                return "Blocked Connections";
            }
            if (chartName === "THConnHits") return "HTTP(s) Blocks";
            if (chartName === "TInvConnHits") return "Invalid Packet Blocks";
            if (chartName === "TIOTConnHits") return "IoT Blocks";
            if (chartName === "TCConnHits") return "Blocked Connections From Device";
            if (chartName === "InPortHits") return "Targeted Ports";
            if (chartName === "SPortHits") return "Source Ports";

            return this.chartDefinitions[chartName]
                ? this.chartDefinitions[chartName].title
                : "Skynet Statistics";
        };

        SkynetUI.getMatchType = function(reason) {
            const value = String(reason || "");
            if (value.slice(-1) === "*") return "Network Range";
            if (value) return "Exact IP / Rule";
            return "";
        };

        SkynetUI.getAssociatedDomains = function(chartName, index) {
            const settings = window.SkynetSettings;

            if (settings && settings.extendedstats === "disabled") {
                return "";
            }

            const domains = window["Label" + chartName + "_AssDomains"];
            const value = Array.isArray(domains) && domains[index]
                ? String(domains[index]).trim()
                : "";

            return value === "*" ? "" : value;
        };

        SkynetUI.showChartDetails = function(chartName, multiLabel, index) {
            const group = this.getElement(chartName + "_Group");
            const groupValue = group ? Number(group.value) : 0;
            const source = this.getChartData(chartName, multiLabel);

            if (!source || source.labels[index] === undefined) return;

            const label = String(source.labels[index]);
            const hits = this.formatNumber(source.data[index]);

            if (chartName === "InPortHits" || chartName === "SPortHits") {
                this.openDetails({
                    title: "Port Details",
                    primary: {
                        label: "Port Number",
                        value: label,
                        copy: true
                    },
                    fields: [
                        { label: "Statistic", value: this.getStatisticName(chartName) },
                        { label: "Port Number", value: label },
                        { label: "Hits", value: hits },
                        { label: "Direction", value: "Inbound" },
                        {
                            label: "Type",
                            value: chartName === "SPortHits" ? "Source Port" : "Target Port"
                        }
                    ],
                    actions: [{
                        label: "SpeedGuide",
                        url: "https://www.speedguide.net/port.php?port=" +
                            encodeURIComponent(label)
                    }]
                });
                return;
            }

            if (multiLabel === "true" && groupValue === 1) {
                this.openDetails({
                    title: "Country Details",
                    primary: {
                        label: "Country",
                        value: this.getCountryName(label),
                        copy: false
                    },
                    fields: [
                        { label: "Statistic", value: this.getStatisticName(chartName) },
                        { label: "Direction", value: this.getDirection(chartName) },
                        { label: "Country", value: this.getCountryName(label) },
                        { label: "Hits", value: hits }
                    ],
                    actions: []
                });
                return;
            }

            const reasons = window["Label" + chartName + "_BanReason"];
            const alienVault = window["Label" + chartName + "_AlienVault"];
            const domains = this.getAssociatedDomains(chartName, index);
            const country = this.getChartCountry(chartName, index);
            const reason = Array.isArray(reasons) ? (reasons[index] || "") : "";

            const fields = [
                { label: "Statistic", value: this.getStatisticName(chartName) }
            ];

            const direction = this.getDirection(chartName);
            if (direction) {
                fields.push({ label: "Direction", value: direction });
            }

            if (chartName === "TCConnHits") {
                const deviceParts = label.match(/^(.+?)\s+\((.+)\)$/);
                const macAddresses = window.LabelTCConnHits_MAC;
                const macAddress = Array.isArray(macAddresses)
                    ? (macAddresses[index] || "Unknown")
                    : "Unknown";

                if (deviceParts) {
                    fields.push({ label: "IP Address", value: deviceParts[1] });
                    fields.push({ label: "Device Name", value: deviceParts[2] });
                } else {
                    fields.push({ label: "IP Address / Device", value: label });
                }

                fields.push({ label: "MAC Address", value: macAddress });

                fields.push({ label: "Hits", value: hits });

                if (country) {
                    fields.push({
                        label: "Country",
                        value: this.getCountryName(country)
                    });
                }

                const devicePrimary = deviceParts
                    ? {
                        label: "Device Name",
                        value: deviceParts[2],
                        copy: true
                    }
                    : {
                        label: "IP Address / Device",
                        value: label,
                        copy: true
                    };

                this.openDetails({
                    title: "Device Details",
                    primary: devicePrimary,
                    fields: fields,
                    actions: []
                });
                return;
            }

            fields.push({ label: "IP Address", value: label });
            fields.push({ label: "Hits", value: hits });

            if (country) {
                fields.push({
                    label: "Country",
                    value: this.getCountryName(country)
                });
            }

            if (reason) {
                fields.push({ label: "Ban Reason", value: reason });

                const matchType = this.getMatchType(reason);
                if (matchType) {
                    fields.push({ label: "Match Type", value: matchType });
                }
            }

            if (domains) {
                fields.push({
                    label: "Associated Domains",
                    value: domains
                });
            }

            this.openDetails({
                title: "IP Details",
                primary: {
                    label: "IP Address",
                    value: label,
                    copy: true
                },
                fields: fields,
                actions: [{
                    label: "AlienVault",
                    url: Array.isArray(alienVault) && alienVault[index]
                        ? alienVault[index]
                        : "https://otx.alienvault.com/indicator/ip/" +
                            encodeURIComponent(label)
                }]
            });
        };

        SkynetUI.bindTableDetails = function() {
            document.querySelectorAll(
                ".StatsTable.skynet-modern-table tbody tr"
            ).forEach(function(row) {
                const ipCell = row.querySelector("td:first-child");

                if (!ipCell) {
                    return;
                }

                const ip = ipCell.textContent.trim();

                if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
                    return;
                }

                ipCell.classList.add("skynet-context-link");
                ipCell.title = "Open Skynet details";

                ipCell.addEventListener("click", function(event) {
                    if (event.target.tagName === "A" ||
                        event.target.tagName === "BUTTON") {
                        return;
                    }

                    const reasonCell = row.querySelector(".skynet-table-reason");
                    const countryCell = row.querySelector(".skynet-table-country");
                    const domainsCell = row.querySelector(".skynet-table-domains");
                    const reason = reasonCell ? reasonCell.textContent.trim() : "";
                    const country = countryCell ? countryCell.textContent.trim() : "";
                    const domains = domainsCell
                        ? (domainsCell.getAttribute("data-domains") ||
                            domainsCell.textContent.trim())
                        : "";
                    const link = row.querySelector("a[href]");

                    const fields = [
                        {
                            label: "Statistic",
                            value: "Blocked Connection"
                        },
                        {
                            label: "IP Address",
                            value: ip
                        }
                    ];

                    if (country) {
                        fields.push({
                            label: "Country",
                            value: SkynetUI.getCountryName(country)
                        });
                    }

                    if (reason) {
                        fields.push({
                            label: "Ban Reason",
                            value: reason
                        });

                        const matchType = SkynetUI.getMatchType(reason);

                        if (matchType) {
                            fields.push({
                                label: "Match Type",
                                value: matchType
                            });
                        }
                    }

                    /* Suppress the stats.js empty-domain placeholder in the detail panel. */
                    if (domains && domains !== "*") {
                        fields.push({
                            label: "Associated Domains",
                            value: domains
                        });
                    }

                    this.classList.add("skynet-context-selected");

                    SkynetUI.openDetails({
                        title: "IP Details",
                        primary: {
                            label: "IP Address",
                            value: ip,
                            copy: true
                        },
                        fields: fields,
                        actions: [{
                            label: "AlienVault",
                            url: link && link.href
                                ? link.href
                                : "https://otx.alienvault.com/indicator/ip/" +
                                    encodeURIComponent(ip)
                        }]
                    });
                });
            });
        };

        SkynetUI.getChartTooltipMeta = function(chartName, multiLabel, index) {
            const source = this.getChartData(chartName, multiLabel);

            if (!source || source.labels[index] === undefined) {
                return null;
            }

            const label = String(source.labels[index]);
            const hits = this.formatNumber(source.data[index]);

            if (chartName === "InPortHits" || chartName === "SPortHits") {
                return {
                    title: chartName === "SPortHits"
                        ? "Source Port " + label
                        : "Target Port " + label,
                    label: "Hits: " + hits,
                    detail: "Inbound"
                };
            }

            const group = this.getElement(chartName + "_Group");
            const groupValue = group ? Number(group.value) : 0;

            if (multiLabel === "true" && groupValue === 1) {
                return {
                    title: "Country: " + this.getCountryName(label),
                    label: "Hits: " + hits,
                    detail: this.getDirection(chartName)
                };
            }

            if (chartName === "TCConnHits") {
                const parts = label.match(/^(.+?)\s+\((.+)\)$/);

                return {
                    title: parts ? "Device: " + parts[2] : "IP Address / Device",
                    label: parts ? "IP: " + parts[1] : label,
                    detail: "Hits: " + hits
                };
            }

            const reasons = window["Label" + chartName + "_BanReason"];
            const country = this.getChartCountry(chartName, index);
            const domains = this.getAssociatedDomains(chartName, index);

            const meta = {
                title: "IP: " + label,
                label: "Hits: " + hits,
                detail: this.getDirection(chartName)
            };

            if (country) {
                meta.country = "Country: " +
                    this.getCountryName(country);
            }

            if (Array.isArray(reasons) && reasons[index]) {
                meta.reason = "Ban Reason: " + reasons[index];
            }

            if (domains) {
                meta.domains = domains.split(/\s+/);
            }

            return meta;
        };

        /* Chart rendering. */
        SkynetUI.drawChart = function(chartName, multiLabel) {
            const canvas = this.getElement("divChart" + chartName);

            if (!canvas) {
                return;
            }

            const source = this.getChartData(chartName, multiLabel);

            this.destroyChart(chartName);

            if (!source) {
                this.showNoData(chartName);
                return;
            }

            const groupElement = this.getElement(chartName + "_Group");
            const groupedByCountry =
                multiLabel === "true" &&
                groupElement &&
                Number(groupElement.value) === 1;

            const chartLabels = groupedByCountry
                ? this.formatChartLabels(source.labels, "country")
                : source.labels;

            this.clearNoData(chartName);

            const configuration = this.getChartConfiguration(chartName);
            const isPie = configuration.type === "doughnut";
            const singleItem = !isPie && source.data.length === 1;
            const textColor = this.getChartTextColor();
            const gridColor = this.getChartGridColor();
            const context = canvas.getContext("2d");
            const chartWidth = canvas.clientWidth || canvas.width;
            const chartHeight = canvas.clientHeight || canvas.height;

            /*
             * Use a compact scale for single-result bar charts so the result
             * remains visually distinct from the chart container.
             */
            const chartContainer = canvas.parentElement;

            if (chartContainer) {
                chartContainer.style.height = singleItem ? "250px" : "";
            }

            const colors = source.data.map(function(_, index) {
                return SkynetUI.getChartColor(index);
            });
            const fills = isPie ? colors : colors.map(function(color) {
                const gradient = configuration.indexAxis === "y"
                    ? context.createLinearGradient(0, 0, chartWidth, 0)
                    : context.createLinearGradient(0, chartHeight, 0, 0);

                gradient.addColorStop(0, "rgba(17, 25, 28, 0.72)");
                gradient.addColorStop(1, color);
                return gradient;
            });

            const dataset = {
                data: source.data,
                borderWidth: 1,
                borderColor: isPie ? "#11191c" : colors,
                backgroundColor: fills,
                hoverBackgroundColor: colors,
                hoverBorderColor: "#dffaff",
                hoverBorderWidth: 2,
                borderRadius: isPie ? 0 : 5,
                borderSkipped: false,
                maxBarThickness: 28,
                barPercentage: 0.74,
                categoryPercentage: 0.82,
                spacing: isPie ? 2 : 0,
                hoverOffset: isPie ? 7 : 0
            };

            const glowPlugin = {
                id: "skynetChartGlow",
                beforeDatasetDraw: function(chart) {
                    chart.ctx.save();
                    chart.ctx.shadowColor = "rgba(53, 216, 255, 0.34)";
                    chart.ctx.shadowBlur = isPie ? 6 : 8;
                },
                afterDatasetDraw: function(chart) {
                    chart.ctx.restore();
                }
            };

            const options = {
                responsive: true,
                maintainAspectRatio: false,
                animation: {
                    duration: 400,
                    easing: "easeOutQuart"
                },
                cutout: isPie ? "56%" : undefined,
                layout: {
                    padding: {
                        top: 8,
                        right: 6,
                        bottom: 8,
                        left: 6
                    }
                },
                interaction: {
                    mode: "nearest",
                    intersect: true
                },
                plugins: {
                    legend: {
                        display: isPie,
                        position: "right",
                        align: "center",
                        title: {
                            display: isPie,
                            text: SkynetUI.getLegendLabel(chartName),
                            color: textColor,
                            font: {
                                size: 11,
                                weight: "bold"
                            },
                            padding: {
                                bottom: 10
                            }
                        },
                        labels: {
                            color: textColor,
                            boxWidth: 10,
                            boxHeight: 10,
                            usePointStyle: true,
                            padding: 7,
                            font: {
                                size: 11
                            },
                            generateLabels: function(chart) {
                                const labels = chart.data.labels || [];
                                const values =
                                    chart.data.datasets[0]
                                        ? chart.data.datasets[0].data || []
                                        : [];

                                return labels.map(function(label, index) {
                                    return {
                                        text: String(label) + " — " +
                                            SkynetUI.formatNumber(values[index]),
                                        fillStyle: chart.data.datasets[0]
                                            .backgroundColor[index],
                                        strokeStyle: chart.data.datasets[0]
                                            .borderColor,
                                        lineWidth: chart.data.datasets[0]
                                            .borderWidth,
                                        hidden: typeof chart.getDataVisibility === "function"
                                            ? !chart.getDataVisibility(index)
                                            : false,
                                        index: index
                                    };
                                });
                            }
                        }
                    },
                    title: {
                        display: false
                    },
                    tooltip: {
                    enabled: true,
                    mode: "nearest",
                    intersect: true,
                    displayColors: false,
                    backgroundColor: "rgba(8, 14, 16, 0.94)",
                    borderColor: "#43565d",
                    borderWidth: 1,
                    boxPadding: 0,
                    padding: 10,
                    caretPadding: 8,
                    titleColor: "#ffffff",
                    titleFont: {
                        size: 12,
                        weight: "bold"
                    },
                    titleMarginBottom: 4,
                    bodyColor: "#dbe4e7",
                    bodyFont: {
                        size: 11
                    },
                    footerColor: "#8fd1f5",
                    footerFont: {
                        size: 10,
                        style: "normal"
                    },
                    xAlign: "left",
                    yAlign: "center",
                    titleAlign: "left",
                    bodyAlign: "left",
                    footerAlign: "left",
                    callbacks: {
                        title: function(items) {
                            if (!items.length) {
                                return "";
                            }

                            const item = items[0];
                            const meta = SkynetUI.getChartTooltipMeta(
                                chartName,
                                multiLabel,
                                item.dataIndex
                            );

                            return meta ? meta.title : "";
                        },
                        label: function(context) {
                            const meta = SkynetUI.getChartTooltipMeta(
                                chartName,
                                multiLabel,
                                context.dataIndex
                            );

                            return meta ? meta.label : "";
                        },
                        afterLabel: function(context) {
                            const meta = SkynetUI.getChartTooltipMeta(
                                chartName,
                                multiLabel,
                                context.dataIndex
                            );

                            if (!meta) {
                                return "";
                            }

                            const lines = [];

                            if (meta.detail) {
                                lines.push(meta.detail);
                            }

                            if (meta.country) {
                                lines.push(meta.country);
                            }

                            if (meta.reason) {
                                lines.push(meta.reason);
                            }

                            if (meta.domains && meta.domains.length) {
                                lines.push("Associated Domains:");
                                meta.domains.forEach(function(domain) {
                                    lines.push("  " + domain);
                                });
                            }

                            return lines;
                        },
                        footer: function() {
                            return "Click for details";
                        }
                    }
                }
                }
            };

            if (!isPie) {
                options.indexAxis = configuration.indexAxis;
                options.scales = {
                    x: {
                        beginAtZero: true,
                        grid: {
                            color: "rgba(143, 209, 245, 0.08)",
                            borderColor: gridColor,
                            tickColor: "rgba(143, 209, 245, 0.12)"
                        },
                        ticks: {
                            color: textColor,
                            precision: 0
                        },
                        title: {
                            display: true,
                            color: textColor,
                            text: this.getAxisLabel(
                                chartName,
                                "x",
                                configuration.indexAxis
                            )
                        }
                    },
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: "rgba(143, 209, 245, 0.08)",
                            borderColor: gridColor,
                            tickColor: "rgba(143, 209, 245, 0.12)"
                        },
                        ticks: {
                            color: textColor,
                            precision: 0
                        },
                        title: {
                            display: true,
                            color: textColor,
                            text: this.getAxisLabel(
                                chartName,
                                "y",
                                configuration.indexAxis
                            )
                        }
                    }
                };

                if (singleItem) {
                    const value = Math.max(Number(source.data[0]) || 0, 0);
                    const suggestedMax = Math.max(
                        value * 1.25,
                        value + 1,
                        10
                    );

                    options.scales.x.suggestedMax = suggestedMax;

                    /*
                     * Simplify the category axis for a single horizontal
                     * result.
                     */
                    options.scales.y.grid.display = false;
                }
            }

            this.charts[chartName] = new Chart(
                context,
                {
                    type: configuration.type,
                    data: {
                        labels: chartLabels,
                        datasets: [dataset]
                    },
                    plugins: [glowPlugin],
                    options: options
                }
            );

            canvas.setAttribute("role", "img");
            canvas.setAttribute("aria-label", chartName + " chart");

            if (!canvas.dataset.skynetClickBound) {
                canvas.addEventListener("click", function(event) {
                    const chart = SkynetUI.charts[chartName];

                    if (!chart) {
                        return;
                    }

                    const elements = chart.getElementsAtEventForMode(
                        event,
                        "nearest",
                        { intersect: true },
                        true
                    );

                    if (!elements.length) {
                        return;
                    }

                    SkynetUI.showChartDetails(
                        chartName,
                        multiLabel,
                        elements[0].index
                    );
                });

                canvas.dataset.skynetClickBound = "true";
            }
        };

        SkynetUI.drawActivityChart = function(chartName) {
            const canvas = this.getElement("divChart" + chartName);

            if (!canvas) {
                return;
            }

            this.destroyChart(chartName);

            const labels = window.LabelActivityToday;

            if (!Array.isArray(labels) || !labels.length || labels[0] === "") {
                this.showNoData(chartName);
                return;
            }

            const series = [
                {
                    label: "Inbound",
                    values: window.DataActivityInbound,
                    color: "#35d8ff",
                    fill: "rgba(53, 216, 255, 0.18)"
                },
                {
                    label: "Outbound",
                    values: window.DataActivityOutbound,
                    color: "#39ef9d",
                    fill: "rgba(57, 239, 157, 0.14)"
                },
                {
                    label: "Invalid",
                    values: window.DataActivityInvalid,
                    color: "#ff5f6d",
                    fill: "rgba(255, 95, 109, 0.12)",
                    setting: "loginvalid"
                },
                {
                    label: "IoT",
                    values: window.DataActivityIOT,
                    color: "#c875ff",
                    fill: "rgba(200, 117, 255, 0.12)",
                    setting: "iotblocked"
                }
            ];
            const context = canvas.getContext("2d");
            const datasets = series.filter(function(item) {
                return Array.isArray(item.values);
            }).map(function(item) {
                const gradient = context.createLinearGradient(0, 0, 0, 270);
                /*
                 * Keep disabled series in the legend for context, but hide
                 * their data and prevent Chart.js from re-enabling them.
                 */
                const disabled = Boolean(item.setting && window.SkynetSettings &&
                    window.SkynetSettings[item.setting] !== "enabled");
                gradient.addColorStop(0, item.fill);
                gradient.addColorStop(1, "rgba(17, 25, 28, 0)");

                return {
                    label: item.label,
                    data: item.values.map(function(value) {
                        return Number(value) || 0;
                    }),
                    borderColor: item.color,
                    backgroundColor: gradient,
                    borderWidth: 2,
                    pointRadius: 1.5,
                    pointHoverRadius: 5,
                    pointBackgroundColor: item.color,
                    pointBorderColor: "#11191c",
                    pointBorderWidth: 1,
                    tension: 0.35,
                    fill: true,
                    hidden: disabled,
                    disabledBySetting: disabled
                };
            });

            const hasActivity = datasets.some(function(dataset) {
                return !dataset.disabledBySetting && dataset.data.some(function(value) {
                    return value > 0;
                });
            });

            if (!hasActivity) {
                this.showNoData(chartName);
                return;
            }

            this.clearNoData(chartName);

            const textColor = this.getChartTextColor();
            const glowPlugin = {
                id: "skynetActivityGlow",
                beforeDatasetDraw: function(chart, args) {
                    chart.ctx.save();
                    chart.ctx.shadowColor = chart.data.datasets[args.index].borderColor;
                    chart.ctx.shadowBlur = 8;
                },
                afterDatasetDraw: function(chart) {
                    chart.ctx.restore();
                }
            };

            this.charts[chartName] = new Chart(context, {
                type: "line",
                data: {
                    labels: labels,
                    datasets: datasets
                },
                plugins: [glowPlugin],
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    animation: {
                        duration: 450,
                        easing: "easeOutQuart"
                    },
                    interaction: {
                        mode: "index",
                        intersect: false
                    },
                    layout: {
                        padding: {
                            top: 4,
                            right: 5,
                            bottom: 2,
                            left: 2
                        }
                    },
                    plugins: {
                        legend: {
                            display: true,
                            position: "top",
                            align: "end",
                            labels: {
                                color: textColor,
                                boxWidth: 8,
                                boxHeight: 8,
                                usePointStyle: true,
                                padding: 14,
                                font: {
                                    size: 11
                                }
                            },
                            onClick: function(event, item, legend) {
                                const chart = legend.chart;
                                const dataset = chart.data.datasets[item.datasetIndex];
                                const meta = chart.getDatasetMeta(item.datasetIndex);

                                if (!dataset || dataset.disabledBySetting) {
                                    return;
                                }
                                meta.hidden = meta.hidden === null
                                    ? !dataset.hidden
                                    : null;
                                chart.update();
                            }
                        },
                        tooltip: {
                            mode: "index",
                            intersect: false,
                            backgroundColor: "rgba(8, 14, 16, 0.94)",
                            borderColor: "#43565d",
                            borderWidth: 1,
                            titleColor: "#ffffff",
                            bodyColor: "#dbe4e7",
                            padding: 10,
                            callbacks: {
                                label: function(item) {
                                    return item.dataset.label + ": " +
                                        SkynetUI.formatNumber(item.parsed.y);
                                }
                            }
                        }
                    },
                    scales: {
                        x: {
                            grid: {
                                color: "rgba(143, 209, 245, 0.06)"
                            },
                            ticks: {
                                color: textColor,
                                maxTicksLimit: 8,
                                maxRotation: 0
                            }
                        },
                        y: {
                            beginAtZero: true,
                            grid: {
                                color: "rgba(143, 209, 245, 0.10)"
                            },
                            ticks: {
                                color: textColor,
                                precision: 0,
                                callback: function(value) {
                                    return SkynetUI.formatNumber(value);
                                }
                            }
                        }
                    }
                }
            });

            canvas.setAttribute("role", "img");
            canvas.setAttribute("aria-label", "Hourly block activity today");
        };

        SkynetUI.groupCountries = function(chartName) {
            const countries = window["Label" + chartName + "_Country"];
            const values = window["Data" + chartName];

            if (!Array.isArray(countries) || !Array.isArray(values)) {
                return;
            }

            const totals = Object.create(null);

            countries.forEach(function(country, index) {
                if (!country) {
                    return;
                }

                totals[country] = (totals[country] || 0) +
                    (Number(values[index]) || 0);
            });

            const sorted = Object.keys(totals)
                .map(function(name) {
                    return {
                        label: name,
                        data: totals[name]
                    };
                })
                .sort(function(a, b) {
                    return b.data - a.data;
                });

            window["Label" + chartName + "_Sorted"] =
                sorted.map(function(entry) { return entry.label; });

            window["Data" + chartName + "_Sum"] =
                sorted.map(function(entry) { return entry.data; });

            delete this.chartData[chartName];
        };

        SkynetUI.setupChart = function(chartName, multiLabel) {
            if (this.charts[chartName]) {
                this.destroyChart(chartName);
            }

            if (this.chartDefinitions[chartName].activity) {
                this.drawActivityChart(chartName);
                return;
            }

            this.restoreSelect(chartName + "_Type", 0, 2);

            if (multiLabel === "true" && this.canGroupByCountry(chartName)) {
                this.restoreSelect(chartName + "_Group", 0, 1);
                this.groupCountries(chartName);
            }

            this.drawChart(chartName, multiLabel);
        };

        SkynetUI.changeChart = function(element, multiLabel) {
            this.storeSelect(element);

            const chartName = element.id.substring(
                0,
                element.id.indexOf("_")
            );

            delete this.chartData[chartName];
            this.drawChart(chartName, multiLabel);
        };

        SkynetUI.setSectionState = function(section, expanded, persist) {
            const table = section.closest(".skynet-section > table") ||
                section.parentElement;
            const empty = section.classList.contains("skynet-section-empty");

            const bodyRows = table
                ? table.querySelectorAll(".skynet-section-body-row")
                : [];

            section.classList.toggle("expanded", expanded);
            section.classList.toggle("collapsed", !expanded);
            section.setAttribute("aria-expanded", expanded ? "true" : "false");

            bodyRows.forEach(function(row) {
                row.style.display = expanded ? "" : "none";
            });

            /* Empty auto-collapse must never overwrite the user's cookie. */
            if (persist !== false && !empty) {
                this.setCookie(
                    section.id,
                    expanded ? "expanded" : "collapsed"
                );
            }

            if (!expanded) {
                const chartName = section.id.replace("skynet_chart_", "");

                if (section.id.indexOf("skynet_chart_") === 0) {
                    this.destroyChart(chartName);
                }
            } else if (!empty && section.id.indexOf("skynet_chart_") === 0) {
                const chartName = section.id.replace("skynet_chart_", "");
                const definition = this.chartDefinitions[chartName];

                if (definition) {
                    this.setupChart(
                        chartName,
                        definition.multiLabel ? "true" : "false"
                    );
                }
            }

            const toggle = section.querySelector(".skynet-section-toggle");

            if (toggle) {
                toggle.textContent = expanded ? "▾" : "▸";
            }

        };

        SkynetUI.setupCollapsibles = function() {
            document.querySelectorAll(".skynet-section-head").forEach(function(section) {
                section.addEventListener("click", function() {
                    SkynetUI.setSectionState(
                        this,
                        !this.classList.contains("expanded")
                    );
                });

                section.addEventListener("keydown", function(event) {
                    if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        SkynetUI.setSectionState(
                            this,
                            !this.classList.contains("expanded")
                        );
                    }
                });
            });

            document.querySelectorAll(".skynet-section-head").forEach(function(section) {
                if (SkynetUI.getCookie(section.id) === "collapsed") {
                    SkynetUI.setSectionState(section, false);
                }
            });
        };

        SkynetUI.buildChartHtml = function(title, name, multiLabel) {
            let html = "";
            html += '<div class="skynet-section">';
            html += '<table width="100%" border="0" cellpadding="0" cellspacing="0">';

            html += '<thead class="collapsible expanded skynet-section-head" id="skynet_chart_' + name + '" aria-expanded="true" role="button" tabindex="0">';
            html += '<tr>';
            html += '<td>' + this.escapeHtml(title) + '</td>';
            html += '<td><span class="skynet-section-toggle" aria-hidden="true">▾</span></td>';
            html += '</tr>';
            html += '</thead>';

            html += '<tbody>';
            html += '<tr class="skynet-section-body-row">';
            html += '<td colspan="2" style="padding:0;">';

            html += '<table class="skynet-controls-table" border="0" cellpadding="0" cellspacing="0">';
            html += '<tr>';

            if (multiLabel === "true" && this.canGroupByCountry(name)) {
                html += '<td class="skynet-controls skynet-control-cell">';
                html += '<span class="skynet-control-label">Group</span> ';
                html += '<select class="input_option" id="' + name + '_Group">';
                html += '<option value="0">IP Address</option>';
                html += '<option value="1">Country</option>';
                html += '</select>';
                html += '</td>';

                html += '<td class="skynet-controls skynet-control-cell">';
            } else {
                html += '<td class="skynet-controls">';
            }

            html += '<span class="skynet-control-label">View</span> ';
            html += '<select class="input_option" id="' + name + '_Type">';
            html += '<option value="0">Horizontal</option>';
            html += '<option value="1">Vertical</option>';
            html += '<option value="2">Doughnut</option>';
            html += '</select>';
            html += '</td>';

            html += '</tr>';
            html += '</table>';

            html += '<div class="skynet-chart-shell">';
            html += '<canvas id="divChart' + name + '"></canvas>';
            html += '</div>';

            html += '</td>';
            html += '</tr>';
            html += '</tbody>';

            html += '</table>';
            html += '</div>';

            return html;
        };

        SkynetUI.buildActivityChartHtml = function(title, name) {
            let html = "";
            html += '<div class="skynet-section">';
            html += '<table width="100%" border="0" cellpadding="0" cellspacing="0">';
            html += '<thead class="collapsible expanded skynet-section-head" id="skynet_chart_' + name + '" aria-expanded="true" role="button" tabindex="0">';
            html += '<tr>';
            html += '<td>' + this.escapeHtml(title) + '</td>';
            html += '<td><span class="skynet-section-toggle" aria-hidden="true">▾</span></td>';
            html += '</tr>';
            html += '</thead>';
            html += '<tbody>';
            html += '<tr class="skynet-section-body-row">';
            html += '<td colspan="2" style="padding:0;">';
            html += '<div class="skynet-chart-shell skynet-activity-shell">';
            html += '<canvas id="divChart' + name + '"></canvas>';
            html += '</div>';
            html += '</td>';
            html += '</tr>';
            html += '</tbody>';
            html += '</table>';
            html += '</div>';

            return html;
        };

        SkynetUI.buildTableHtml = function(title, name) {
            const ips = window["Label" + name + "_IPs"];
            const settings = window.SkynetSettings;
            const showCountry = !settings || settings.lookupcountry !== "disabled";
            const showDomains = !settings || settings.extendedstats !== "disabled";
            const columnCount = 3 + (showCountry ? 1 : 0) + (showDomains ? 1 : 0);
            const noData = !Array.isArray(ips) ||
                !ips.length ||
                (ips.length === 1 && ips[0] === "");

            let html = "";
            html += '<div class="skynet-section">';
            html += '<table width="100%" border="0" cellpadding="0" cellspacing="0">';

            html += '<thead class="collapsible ' +
                (noData ? 'collapsed skynet-section-empty' : 'expanded') +
                ' skynet-section-head" id="skynet_table_' + name +
                '" aria-expanded="' + (noData ? 'false' : 'true') +
                '" role="button" tabindex="0">';
            html += '<tr>';
            html += '<td>' + this.escapeHtml(title) +
                (noData ? '<span class="skynet-empty-badge">No activity</span>' : '') +
                '</td>';
            html += '<td><span class="skynet-section-toggle" aria-hidden="true">' +
                (noData ? '▸' : '▾') + '</span></td>';
            html += '</tr>';
            html += '</thead>';

            html += '<tbody>';
            html += '<tr class="skynet-section-body-row"' +
                (noData ? ' style="display:none;"' : '') + '>';
            html += '<td colspan="2" style="padding:0;">';
            html += '<div class="skynet-table-shell">';

            html += '<table class="FormTable StatsTable skynet-modern-table">';

            if (noData) {
                html += '<tr><td colspan="' + columnCount + '" class="skynet-nodata skynet-table-nodata">No data to display</td></tr>';
            } else {
                html += '<col style="width:120px;">';
                html += showDomains
                    ? '<col style="width:' + (showCountry ? '245px' : '285px') + ';">'
                    : '<col style="width:auto;">';
                html += '<col style="width:82px;">';
                if (showCountry) {
                    html += '<col style="width:80px;">';
                }
                if (showDomains) {
                    html += '<col style="width:auto;">';
                }

                html += '<thead><tr>';
                html += '<th>IP Address</th>';
                html += '<th>Ban Reason</th>';
                html += '<th class="skynet-table-details">Details</th>';
                if (showCountry) {
                    html += '<th class="skynet-table-country">Country</th>';
                }
                if (showDomains) {
                    html += '<th class="skynet-table-domains">Associated Domains</th>';
                }
                html += '</tr></thead>';

                const reasons = window["Label" + name + "_BanReason"] || [];
                const alienVault = window["Label" + name + "_AlienVault"] || [];
                const countries = showCountry
                    ? window["Label" + name + "_Country"] || []
                    : [];
                const domains = showDomains
                    ? window["Label" + name + "_AssDomains"] || []
                    : [];

                ips.forEach(function(ip, index) {
                    const escapedIp = SkynetUI.escapeHtml(ip);
                    const escapedReason = SkynetUI.escapeHtml(reasons[index] || "");
                    const escapedCountry = SkynetUI.escapeHtml(countries[index] || "");
                    const url = SkynetUI.escapeHtml(alienVault[index] || "#");

                    html += '<tr>';
                    html += '<td><span class="skynet-ip-value">' + escapedIp + '</span></td>';
                    html += '<td class="skynet-table-reason">' + escapedReason + '</td>';
                    html += '<td class="skynet-table-details"><a class="skynet-external-link" target="_blank" rel="noopener" href="' +
                        url + '">View</a></td>';
                    if (showCountry) {
                        html += '<td class="skynet-table-country">' + escapedCountry + '</td>';
                    }
                    if (showDomains) {
                        const domainValue = domains[index] === "*"
                            ? ""
                            : domains[index] || "";
                        const domainItems = domainValue.trim()
                            ? domainValue.trim().split(/\s+/)
                            : [];
                        const previewDomains = domainItems.slice(0, 3);
                        const remainingDomains = domainItems.length - previewDomains.length;
                        const escapedDomainValue = SkynetUI.escapeHtml(domainItems.join(" "));
                        const escapedDomainTitle = domainItems.map(function(domain) {
                            return SkynetUI.escapeHtml(domain);
                        }).join("&#10;");
                        const escapedDomainPreview = previewDomains.map(function(domain) {
                            return SkynetUI.escapeHtml(domain);
                        }).join("<br />");

                        html += '<td class="skynet-table-domains" data-domains="' +
                            escapedDomainValue + '" title="' + escapedDomainTitle + '">';
                        html += '<span class="skynet-domain-preview">' +
                            escapedDomainPreview + '</span>';
                        if (remainingDomains > 0) {
                            html += '<span class="skynet-domain-more">+' +
                                remainingDomains + ' more</span>';
                        }
                        html += '</td>';
                    }
                    html += '</tr>';
                });
            }

            html += '</table>';
            html += '</div>';
            html += '</td>';
            html += '</tr>';
            html += '</tbody>';

            html += '</table>';
            html += '</div>';

            return html;
        };

        SkynetUI.applyStatsPayload = function() {
            [
                "SetStatsDate", "SetStatsSize", "SetBLCount1", "SetBLCount2",
                "SetHits1", "SetHits2"
            ].forEach(function(functionName) {
                if (typeof window[functionName] === "function") {
                    window[functionName]();
                }
            });

            /* Accept both the legacy labeled payload and the compact format. */
            const statsDate = this.getElement("statsdate");
            const statsSize = this.getElement("statssize");

            if (statsDate) {
                statsDate.textContent = statsDate.textContent
                    .replace(/^Monitoring From\s*/i, "")
                    .replace(/\s+To\s+/i, " — ")
                    .trim() || "N/A";
            }
            if (statsSize) {
                statsSize.textContent = statsSize.textContent
                    .replace(/^Log Size\s*-\s*\(?/i, "")
                    .replace(/\)\s*$/, "")
                    .trim() || "N/A";
            }

        };

        /* Settings, country and IoT management. */
        SkynetUI.populateMalwareStatus = function() {
            const status = this.getElement(this.selectors.malwareStatus);
            const settings = window.SkynetSettings || {};
            const updated = Number(settings.banmalwarelastupdated);

            if (!status) {
                return;
            }

            if (!this.canUpdateMalware()) {
                status.textContent = "Reload settings after updating Skynet.";
                return;
            }

            if (Number.isFinite(updated) && updated > 0) {
                status.textContent = "Last updated " +
                    new Date(updated * 1000).toLocaleString();
            } else {
                status.textContent = "Last update not recorded";
            }
        };

        SkynetUI.canUpdateMalware = function() {
            const settings = window.SkynetSettings;

            return Boolean(settings && window.SkynetSettingsGenerated &&
                Object.prototype.hasOwnProperty.call(settings, "banmalwarelastupdated"));
        };

        SkynetUI.normaliseFeedExclusions = function(value) {
            const names = [];
            const seen = Object.create(null);

            String(value || "").split(/\s+/).forEach(function(name) {
                const key = name.toLowerCase();

                if (/^[A-Za-z0-9._-]+$/.test(name) && !seen[key]) {
                    seen[key] = true;
                    names.push(name);
                }
            });
            return names;
        };

        SkynetUI.getFeedSignature = function(names) {
            return this.normaliseFeedExclusions((names || []).join(" "))
                .map(function(name) { return name.toLowerCase(); })
                .sort()
                .join(" ");
        };

        SkynetUI.isFeedExcluded = function(name) {
            const key = String(name || "").toLowerCase();

            return this.feedExclusions.some(function(excluded) {
                return excluded.toLowerCase() === key;
            });
        };

        SkynetUI.canManageFeeds = function() {
            const summary = window.SkynetFeedSummary;

            return Boolean(window.SkynetSettings && window.SkynetSettingsGenerated &&
                summary && summary.available && Array.isArray(window.SkynetFeeds));
        };

        SkynetUI.isFeedDirty = function() {
            return this.getFeedSignature(this.feedExclusions) !== this.feedOriginal;
        };

        SkynetUI.getFeedState = function(feed) {
            if (this.isFeedExcluded(feed.name)) {
                return "excluded";
            }
            if (feed.state === "excluded") {
                return Number(feed.entries) > 0 ? "cached" : "failed";
            }
            return /^(current|cached|failed)$/.test(feed.state)
                ? feed.state
                : "failed";
        };

        SkynetUI.formatRelativeTime = function(epoch) {
            const seconds = Math.max(0, Math.floor(Date.now() / 1000) - Number(epoch || 0));

			if (!Number(epoch)) return "Never";
			if (seconds < 60) return "Just now";
			if (seconds < 3600) return Math.max(1, Math.floor(seconds / 60)) + "m ago";
			if (seconds < 86400) return Math.floor(seconds / 3600) + "h ago";
			return Math.floor(seconds / 86400) + "d ago";
		};

		SkynetUI.formatAge = function(epoch) {
			const relative = this.formatRelativeTime(epoch);
			return relative === "Never" ? "Change unknown" : "Changed " + relative.toLowerCase();
        };

        SkynetUI.renderFeeds = function() {
            const list = this.getElement(this.selectors.feedList);
            const status = this.getElement(this.selectors.feedStatus);
            const header = this.getElement("skynetFeedHeader");
            const feeds = Array.isArray(window.SkynetFeeds) ? window.SkynetFeeds : [];

            if (!list) {
                return;
            }
            list.textContent = "";

            if (!this.canManageFeeds() || !feeds.length) {
                if (header) header.hidden = true;
                const empty = document.createElement("div");
                empty.className = "skynet-feed-empty";
                empty.textContent = "Source details will be available after the next malware update.";
                list.appendChild(empty);
                if (status) status.textContent = "";
                this.updateFeedControls();
                return;
            }

            if (header) header.hidden = false;
            let enabledCount = 0;
            const stateCounts = {current: 0, cached: 0, failed: 0, excluded: 0};
            feeds.forEach(function(feed) {
                const enabled = !SkynetUI.isFeedExcluded(feed.name);
                const state = SkynetUI.getFeedState(feed);
                const row = document.createElement("div");
                const source = document.createElement("div");
                const entries = document.createElement("div");
                const success = document.createElement("div");
                const successTime = document.createElement("span");
                const contentChange = document.createElement("span");
                const pillCell = document.createElement("div");
                const pill = document.createElement("span");
                const toggleCell = document.createElement("label");
                const toggle = document.createElement("input");
                const toggleSwitch = document.createElement("span");

                if (enabled) enabledCount += 1;
                stateCounts[state] += 1;
                row.className = "skynet-feed-row";
                source.className = "skynet-feed-source";
                source.textContent = feed.name;
                source.title = feed.url;
                entries.className = "skynet-feed-entries";
                entries.textContent = SkynetUI.formatNumber(Number(feed.entries) || 0);
                success.className = "skynet-feed-success";
                successTime.textContent = Number(feed.success) > 0
                    ? new Date(Number(feed.success) * 1000).toLocaleString()
                    : "Never";
                contentChange.className = "skynet-feed-change";
                contentChange.textContent = SkynetUI.formatAge(feed.changed);
                if (Number(feed.changed) > 0) {
                    contentChange.title = new Date(Number(feed.changed) * 1000).toLocaleString();
                }
                success.appendChild(successTime);
                success.appendChild(contentChange);
                pill.className = "skynet-feed-pill " + state;
                pill.textContent = state.charAt(0).toUpperCase() + state.substring(1);
                pillCell.className = "skynet-feed-state";
                pillCell.appendChild(pill);
                toggleCell.className = "skynet-feed-toggle";
                toggle.title = enabled ? "Disable " + feed.name : "Enable " + feed.name;
                toggle.type = "checkbox";
                toggle.checked = enabled;
                toggle.disabled = SkynetUI.refreshInProgress;
                toggle.setAttribute("aria-label", toggle.title);
                toggleSwitch.className = "skynet-feed-switch";
                toggle.addEventListener("change", function() {
                    SkynetUI.toggleFeed(feed.name, this.checked);
                });
                toggleCell.appendChild(toggle);
                toggleCell.appendChild(toggleSwitch);
                row.appendChild(source);
                row.appendChild(entries);
                row.appendChild(success);
                row.appendChild(pillCell);
                row.appendChild(toggleCell);
                list.appendChild(row);
            });

            if (status && !this.refreshInProgress) {
                let message = enabledCount + " of " + feeds.length + " sources enabled";
                if (stateCounts.cached) message += " · " + stateCounts.cached + " cached";
                if (stateCounts.failed) message += " · " + stateCounts.failed + " failed";
                status.textContent = message + ".";
                status.classList.remove("error", "warning");
            }
            this.updateFeedControls();
        };

        SkynetUI.populateFeeds = function() {
            const settings = window.SkynetSettings || {};

            this.feedExclusions = this.normaliseFeedExclusions(settings.excludelists);
            this.feedOriginal = this.getFeedSignature(this.feedExclusions);
            this.renderFeeds();
        };

        SkynetUI.toggleFeed = function(name, enabled) {
            if (this.refreshInProgress || !this.canManageFeeds()) {
                return;
            }
            const feeds = window.SkynetFeeds || [];
            const enabledCount = feeds.filter(function(feed) {
                return !SkynetUI.isFeedExcluded(feed.name);
            }).length;
            const key = String(name).toLowerCase();

            if (!enabled && enabledCount <= 1) {
                this.renderFeeds();
                this.setUpdateResult(
                    "At least one malware source must remain enabled.",
                    true,
                    this.selectors.feedStatus
                );
                return;
            }
            this.feedExclusions = this.feedExclusions.filter(function(excluded) {
                return excluded.toLowerCase() !== key;
            });
            if (!enabled) {
                this.feedExclusions.push(name);
            }
            this.renderFeeds();
        };

        SkynetUI.updateFeedControls = function() {
            const apply = this.getElement(this.selectors.feedButton);

            if (apply) {
                apply.disabled = this.refreshInProgress || !this.canManageFeeds() ||
                    !this.isFeedDirty();
            }
            document.querySelectorAll("#skynetFeedList input[type='checkbox']")
                .forEach(function(toggle) {
                    toggle.disabled = SkynetUI.refreshInProgress ||
                        !SkynetUI.canManageFeeds();
                });
        };

        SkynetUI.getSettingsOptions = function() {
            return [
                "skynetAutoUpdate", "skynetMalwareUpdates", "skynetMalwareUrl",
                "skynetFilterTraffic", "skynetUnbanPrivate", "skynetAiProtect",
                "skynetSecureMode", "skynetLogInvalid", "skynetLogSize",
                "skynetExtendedStats", "skynetCountryLookup", "skynetCdnWhitelist"
            ].map(function(id) {
                return (SkynetUI.getElement(id) || {}).value || "";
            }).join("|");
        };

        SkynetUI.isSettingsDirty = function() {
            return this.getSettingsOptions() !== this.settingsOriginal;
        };

        SkynetUI.updateSettingsControls = function() {
            const apply = this.getElement(this.selectors.settingsButton);

            if (apply) {
                apply.disabled = this.refreshInProgress ||
                    !window.SkynetSettings || !window.SkynetSettingsGenerated ||
                    !this.isSettingsDirty();
            }
        };

        SkynetUI.populateBlacklistCounts = function(settings) {
            const counters = {
                blcount1: settings.blacklist1count,
                blcount2: settings.blacklist2count
            };

            Object.keys(counters).forEach(function(id) {
                const counter = SkynetUI.getElement(id);

                if (counter && /^\d+$/.test(String(counters[id] || ""))) {
                    counter.textContent = SkynetUI.formatNumber(counters[id]);
                }
            });
        };

        SkynetUI.normaliseCountries = function(value) {
            /* Only canonical ISO-style two-letter codes cross the WebUI boundary. */
            const countries = [];

            String(value || "").toLowerCase().split(/\s+/).forEach(function(code) {
                if (/^[a-z]{2}$/.test(code) && countries.indexOf(code) === -1) {
                    countries.push(code);
                }
            });

            return countries.sort();
        };

        SkynetUI.canManageCountries = function() {
            const settings = window.SkynetSettings;

            return Boolean(settings && window.SkynetSettingsGenerated &&
                Object.prototype.hasOwnProperty.call(settings, "countrylist"));
        };

        SkynetUI.isCountryDirty = function() {
            return this.countrySelection.join(" ") !== this.countryOriginal;
        };

        SkynetUI.populateCountryPicker = function() {
            const picker = this.getElement(this.selectors.countryPicker);

            if (!picker) {
                return;
            }

            while (picker.firstChild) {
                picker.removeChild(picker.firstChild);
            }

            const placeholder = document.createElement("option");
            placeholder.value = "";
            placeholder.textContent = "Add a country...";
            picker.appendChild(placeholder);

            this.countryCodes.slice().sort(function(first, second) {
                return SkynetUI.getCountryName(first).localeCompare(
                    SkynetUI.getCountryName(second)
                );
            }).forEach(function(code) {
                const option = document.createElement("option");

                option.value = code.toLowerCase();
                option.textContent = SkynetUI.getCountryName(code) + " (" + code + ")";
                option.disabled = SkynetUI.countrySelection.indexOf(option.value) !== -1;
                picker.appendChild(option);
            });

            picker.value = "";
        };

        SkynetUI.updateCountryControls = function() {
            const supported = this.canManageCountries();
            const busy = this.refreshInProgress;
            const picker = this.getElement(this.selectors.countryPicker);
            const apply = this.getElement(this.selectors.countryButton);
            const refresh = this.getElement(this.selectors.countryRefresh);
            const clear = this.getElement(this.selectors.countryClear);

            if (picker) {
                picker.disabled = busy || !supported;
            }
            if (apply) {
                apply.disabled = busy || !supported || !this.isCountryDirty();
            }
            if (refresh) {
                refresh.disabled = busy || !supported || !this.countrySelection.length ||
                    this.isCountryDirty();
            }
            if (clear) {
                clear.disabled = busy || !supported || !this.countrySelection.length;
            }
            document.querySelectorAll(".skynet-country-remove:not(.skynet-iot-remove):not(.skynet-iot-port-remove):not(.skynet-rule-tag-remove)").forEach(function(button) {
                button.disabled = busy || !supported;
            });
        };

        SkynetUI.renderCountries = function() {
            const apply = this.getElement(this.selectors.countryButton);
            if (apply && !this.refreshInProgress) {
                apply.value = "Apply Countries";
            }

            this.setUpdateResult(
                this.isCountryDirty()
                    ? "Unsaved country blocking changes."
                    : (this.countrySelection.length
                        ? this.countrySelection.length +
                            (this.countrySelection.length === 1 ? " country blocked." : " countries blocked.")
                        : ""),
                false,
                this.selectors.countryResult
            );
            this.renderCountryHealth();
            this.updateCountryControls();
        };

        SkynetUI.populateCountries = function() {
            if (!this.canManageCountries()) {
                this.countrySelection = [];
                this.countryOriginal = "";
                this.populateCountryPicker();
                this.renderCountries();
                this.setUpdateResult(
                    "Reload settings after updating Skynet.",
                    false,
                    this.selectors.countryResult
                );
                return;
            }

            this.countrySelection = this.normaliseCountries(
                window.SkynetSettings.countrylist
            );
            this.countryOriginal = this.countrySelection.join(" ");
            this.populateCountryPicker();
            this.renderCountries();
        };

        SkynetUI.addCountry = function(code) {
            code = String(code || "").toLowerCase();

            if (!/^[a-z]{2}$/.test(code) ||
                this.countrySelection.indexOf(code) !== -1) {
                return;
            }

            this.countrySelection.push(code);
            this.countrySelection.sort();
            this.populateCountryPicker();
            this.renderCountries();
        };

        SkynetUI.removeCountry = function(code) {
            const index = this.countrySelection.indexOf(code);

            if (index === -1 || this.refreshInProgress) {
                return;
            }

            this.countrySelection.splice(index, 1);
            this.populateCountryPicker();
            this.renderCountries();
        };

        SkynetUI.clearCountries = function() {
            if (this.refreshInProgress || !this.countrySelection.length) {
                return;
            }

            this.countrySelection = [];
            this.populateCountryPicker();
            this.renderCountries();
        };

        SkynetUI.renderCountryHealth = function() {
            const list = this.getElement(this.selectors.countryHealth);
            const header = this.getElement("skynetCountryHealthHeader");
            const sources = Array.isArray(window.SkynetCountries)
                ? window.SkynetCountries
                : [];
            const sourceMap = {};
            const original = String(this.countryOriginal || "").split(" ")
                .filter(Boolean);

            if (!list) return;
            list.textContent = "";
            if (!this.countrySelection.length) {
                if (header) header.hidden = true;
                const empty = document.createElement("div");
                empty.className = "skynet-feed-empty";
                empty.textContent = "No countries are currently blocked.";
                list.appendChild(empty);
                return;
            }
            sources.forEach(function(source) {
                sourceMap[String(source.code || "").toLowerCase()] = source;
            });
            if (header) header.hidden = false;
            this.countrySelection.forEach(function(code) {
                const source = sourceMap[code] || {};
                const pending = original.indexOf(code) === -1;
                const stateValue = pending
                    ? "pending"
                    : (/^(current|cached|failed)$/.test(source.state)
                        ? source.state : "pending");
                const row = document.createElement("div");
                const name = document.createElement("span");
                const count = document.createElement("span");
                const date = document.createElement("span");
                const state = document.createElement("span");
                const pill = document.createElement("span");
                const remove = document.createElement("button");

                row.className = "skynet-country-health-row";
                name.className = "skynet-country-health-name";
                name.textContent = SkynetUI.getCountryName(code) +
                    " (" + code.toUpperCase() + ")";
                count.className = "skynet-country-health-count";
                count.textContent = pending || !source.code
                    ? "—" : Number(source.entries || 0).toLocaleString();
                date.className = "skynet-country-health-date";
                date.textContent = pending
                    ? "After apply"
                    : (Number(source.success)
                    ? new Date(Number(source.success) * 1000).toLocaleString()
                    : "Not checked");
                date.title = date.textContent;
                state.className = "skynet-country-health-state";
                pill.className = "skynet-feed-pill " + stateValue;
                pill.textContent = stateValue.charAt(0).toUpperCase() +
                    stateValue.slice(1);
                state.appendChild(pill);
                remove.type = "button";
                remove.className = "skynet-country-remove skynet-country-health-remove";
                remove.dataset.country = code;
                remove.title = "Remove " + SkynetUI.getCountryName(code);
                remove.setAttribute("aria-label", remove.title);
                remove.textContent = "×";
                remove.disabled = SkynetUI.refreshInProgress;
                row.appendChild(name);
                row.appendChild(count);
                row.appendChild(date);
                row.appendChild(state);
                row.appendChild(remove);
                list.appendChild(row);
            });
        };

        SkynetUI.canManageRules = function() {
            return Boolean(window.SkynetSettings && window.SkynetSettingsGenerated &&
                window.SkynetRuleSummary && window.SkynetRuleSummary.available &&
                Array.isArray(window.SkynetRules));
        };

        SkynetUI.canRefreshRules = function() {
            const summary = window.SkynetRuleSummary || {};
            return this.canManageRules() &&
                (Number(summary.domains || 0) + Number(summary.asns || 0) > 0);
        };

        SkynetUI.isRuleRequestApplied = function() {
            const rules = Array.isArray(window.SkynetRules) ? window.SkynetRules : [];
            const operation = custom_settings.skynet_ruleoperation;
            const action = custom_settings.skynet_ruleaction;
            const mode = custom_settings.skynet_rulemode;
            const target = custom_settings.skynet_ruletarget;
            const savedComment = custom_settings.skynet_rulesavedcomment;
            const entries = String(custom_settings.skynet_ruleentries || "")
                .split(/\s+/).filter(Boolean);

            if (!entries.length) return false;
            const ruleExists = function(entry) {
                return rules.some(function(rule) {
                    if (mode === "manual") {
                        return rule.kind === "manual" && rule.action === action &&
                            rule.target === target && rule.entry === entry &&
                            rule.comment === savedComment;
                    }
                    if (mode === "import") {
                        return rule.kind === "import" && rule.action === action &&
                            rule.target === target && rule.comment === savedComment;
                    }
                    if (mode === "domain" || mode === "asn") {
                        return rule.kind === "group" && rule.action === action &&
                            rule.type === mode &&
                            String(rule.entry).toLowerCase() === entry.toLowerCase();
                    }
                    return rule.kind === "manual" && rule.action === action &&
                        rule.entry === entry;
                });
            };
            const matched = entries.every(ruleExists);

            return operation === "add" ? matched : !matched;
        };

        SkynetUI.normaliseRuleEntries = function(value, mode) {
            const entries = [];
            const seen = Object.create(null);
            let invalid = false;

            String(value || "").trim().split(/\s+/).forEach(function(raw) {
                let entry = raw;
                if (!entry) return;
                if (mode === "domain") entry = entry.toLowerCase().replace(/\.$/, "");
                if (mode === "asn") entry = entry.toUpperCase();
                const validDomain = entry.length >= 1 && entry.length <= 253 &&
                    entry.split(".").every(function(label) {
                        return label.length >= 1 && label.length <= 63 &&
                            /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label);
                    });
                const valid = mode === "ip"
                    ? SkynetUI.isIPv4Range(entry)
                    : (mode === "domain"
                        ? validDomain
                        : /^AS[0-9]{1,6}$/.test(entry));
                if (!valid) {
                    invalid = true;
                } else if (!seen[entry]) {
                    seen[entry] = true;
                    entries.push(entry);
                }
            });
            return invalid ? null : entries;
        };

        SkynetUI.renderRuleTags = function() {
            const list = this.getElement(this.selectors.ruleTags);
            if (!list) return;
            list.textContent = "";
            if (!this.ruleEntries.length) {
                const empty = document.createElement("span");
                empty.className = "skynet-country-empty";
                empty.textContent = "Add one or more entries to stage a rule.";
                list.appendChild(empty);
            } else {
                this.ruleEntries.forEach(function(entry) {
                    const tag = document.createElement("span");
                    const remove = document.createElement("button");
                    tag.className = "skynet-rule-tag";
                    tag.appendChild(document.createTextNode(entry));
                    remove.type = "button";
                    remove.className = "skynet-country-remove skynet-rule-tag-remove";
                    remove.dataset.entry = entry;
                    remove.setAttribute("aria-label", "Remove " + entry);
                    remove.textContent = "×";
                    tag.appendChild(remove);
                    list.appendChild(tag);
                });
            }
            this.updateRuleControls();
        };

        SkynetUI.addRuleEntries = function() {
            const input = this.getElement(this.selectors.ruleInput);
            const mode = this.getElement(this.selectors.ruleMode).value;
            const raw = input ? input.value : "";
            const parsed = this.normaliseRuleEntries(raw, mode);

            if (!parsed || !parsed.length) {
                this.setUpdateResult(
                    parsed === null
                        ? "Every entry in the batch must be valid."
                        : (mode === "ip" ? "Enter valid IPv4 addresses or CIDR ranges."
                            : (mode === "domain" ? "Enter valid domain names." : "Enter AS numbers such as AS13335.")),
                    true,
                    this.selectors.ruleResult
                );
                return;
            }
            parsed.forEach(function(entry) {
                if (SkynetUI.ruleEntries.indexOf(entry) === -1) {
                    SkynetUI.ruleEntries.push(entry);
                }
            });
            if (input) input.value = "";
            this.setUpdateResult("", false, this.selectors.ruleResult);
            this.renderRuleTags();
        };

        SkynetUI.removeRuleEntry = function(entry) {
            const index = this.ruleEntries.indexOf(entry);
            if (index !== -1 && !this.refreshInProgress) {
                this.ruleEntries.splice(index, 1);
                this.renderRuleTags();
            }
        };

        SkynetUI.updateRuleControls = function() {
            const supported = this.canManageRules();
            const busy = this.refreshInProgress;
            const action = this.getElement(this.selectors.ruleAction);
            const mode = this.getElement(this.selectors.ruleMode);
            const comment = this.getElement(this.selectors.ruleComment);
            const apply = this.getElement(this.selectors.ruleButton);
            const refresh = this.getElement(this.selectors.ruleRefresh);
            const unban = action && action.value === "unban";
            if (comment && mode) {
                comment.disabled = busy || !supported || mode.value !== "ip" || unban;
                comment.placeholder = unban
                    ? "Not used when unbanning"
                    : (mode.value === "ip" ? "Optional comment" : "Stored by rule name");
            }
            [this.selectors.ruleAction, this.selectors.ruleMode,
                this.selectors.ruleInput, this.selectors.ruleAdd,
                this.selectors.ruleFilter, this.selectors.ruleSearch].forEach(function(id) {
                const control = SkynetUI.getElement(id);
                if (control) control.disabled = busy || !supported;
            });
            if (apply) apply.disabled = busy || !supported || !this.ruleEntries.length;
            if (refresh) refresh.disabled = busy || !this.canRefreshRules();
            document.querySelectorAll(".skynet-rule-remove, .skynet-rule-tag-remove")
                .forEach(function(button) { button.disabled = busy || !supported; });
        };

        SkynetUI.renderRules = function() {
            const list = this.getElement(this.selectors.ruleList);
            const search = this.getElement(this.selectors.ruleSearch);
            const query = search ? search.value.trim().toLowerCase() : "";
            const rules = Array.isArray(window.SkynetRules) ? window.SkynetRules : [];
            if (!list) return;
            list.textContent = "";
			const visible = rules.map(function(rule, index) {
				return { rule: rule, index: index };
			}).filter(function(item) {
				const rule = item.rule;
                const filterMatch = SkynetUI.ruleFilter === "all" ||
                    (SkynetUI.ruleFilter === "imports" && rule.kind === "import") ||
                    (SkynetUI.ruleFilter === "bans" && rule.action === "ban" && rule.kind !== "import") ||
                    (SkynetUI.ruleFilter === "whitelists" && rule.action === "whitelist" && rule.kind !== "import");
                const searchText = [rule.action, rule.type, rule.display,
                    rule.entry, rule.comment].join(" ").toLowerCase();
                return filterMatch && (!query || searchText.indexOf(query) !== -1);
            });
            if (!this.canManageRules() || !visible.length) {
                const empty = document.createElement("div");
                empty.className = "skynet-feed-empty";
                empty.textContent = this.canManageRules()
                    ? "No rules match the current filter."
                    : "Rule details are not currently available.";
                list.appendChild(empty);
                this.updateRuleControls();
                return;
            }
			visible.forEach(function(item) {
				const rule = item.rule;
                const row = document.createElement("div");
                const type = document.createElement("span");
                const entry = document.createElement("span");
                const comment = document.createElement("span");
                const count = document.createElement("span");
                const remove = document.createElement("button");
                const key = [rule.kind, rule.action, rule.type, rule.target,
                    rule.entry, rule.comment].join("|");
                row.className = "skynet-rule-row";
                type.className = "skynet-rule-type " + rule.action;
                const ruleTypeLabels = {
                    ip: "IP",
                    range: "CIDR",
                    cidr: "CIDR",
                    domain: "Domain",
                    asn: "ASN"
                };
                const ruleType = ruleTypeLabels[String(rule.type).toLowerCase()]
                    || String(rule.type).toUpperCase();
                const ruleAction = rule.action === "ban" ? "Ban" : "Whitelist";
                type.textContent = ruleType + " " + ruleAction;
                entry.className = "skynet-rule-entry";
                entry.textContent = rule.kind === "manual"
                    ? rule.entry
                    : (rule.display || rule.entry);
                entry.title = entry.textContent;
                comment.className = "skynet-rule-comment";
				if (String(rule.type).toLowerCase() === "domain") {
					const state = /^(current|cached|empty|expired|failed)$/.test(rule.state)
						? rule.state : "pending";
					const pill = document.createElement("span");
					const age = document.createElement("span");
					comment.className += " freshness skynet-rule-freshness";
					pill.className = "skynet-feed-pill " + state;
					pill.textContent = SkynetUI.formatRuleState(state);
					age.className = "skynet-rule-age";
					age.textContent = Number(rule.success)
						? SkynetUI.formatRelativeTime(rule.success)
						: "Never resolved";
					comment.title = "Last success: " + (Number(rule.success)
						? new Date(Number(rule.success) * 1000).toLocaleString() : "Never") +
						" | Last checked: " + (Number(rule.checked)
							? new Date(Number(rule.checked) * 1000).toLocaleString() : "Never");
					comment.appendChild(pill);
					comment.appendChild(age);
				} else {
					comment.textContent = rule.kind === "manual"
						? (rule.display || "—")
						: "—";
					comment.title = comment.textContent;
				}
                count.className = "skynet-rule-count";
				const ruleCount = Number(rule.count);
				count.textContent = (isNaN(ruleCount) ? 1 : ruleCount).toLocaleString();
                remove.type = "button";
                remove.className = "button_gen skynet-update-button skynet-settings-reload skynet-rule-remove";
                remove.value = "Remove";
                remove.textContent = SkynetUI.ruleConfirm === key ? "Confirm" : "Remove";
				remove.dataset.ruleIndex = String(item.index);
                remove.dataset.ruleKey = key;
                row.appendChild(type);
                row.appendChild(entry);
                row.appendChild(comment);
                row.appendChild(count);
                row.appendChild(remove);
                list.appendChild(row);
            });
            this.updateRuleControls();
        };

		SkynetUI.formatRuleState = function(state) {
			return {
				current: "Current",
				cached: "Cached",
				pending: "Pending",
				empty: "No Address",
				expired: "Expired",
				failed: "Failed"
			}[state] || "Unknown";
		};

		SkynetUI.formatActionLabel = function(action) {
			const area = String(action.area || "");
			const operation = String(action.operation || "");
			const target = String(action.target || "");
			const type = String(action.type || "");
			const ruleType = {ip: "IP", range: "CIDR", address: "IP/CIDR", domain: "domain", asn: "ASN"}[type] || type;
			if (area === "rules" && operation === "refresh" && type === "logical") return "Refreshed dynamic rules";
			if (area === "rules" && operation === "refresh" && type === "whitelist") return "Refreshed whitelist sources";
			if (area === "rules" && operation === "remove" && type === "comment") return "Removed bans by comment";
			if (area === "rules" && operation === "remove" && type === "automatic") return "Removed automatic bans";
			if (area === "rules" && operation === "remove" && type === "all") return "Cleared all bans";
			if (area === "rules" && operation === "add" && type === "import") return "Imported " + target + " list";
			if (area === "rules" && operation === "remove" && type === "import") return "Removed imported " + target + " list";
			if (area === "rules" && operation === "add") return "Added " + [ruleType, target].filter(Boolean).join(" ");
			if (area === "rules" && operation === "remove") return "Removed " + [ruleType, target].filter(Boolean).join(" ");
			if (area === "feeds" && operation === "remove") return "Cleared threat feed entries";
			if (area === "feeds") return "Updated threat feeds";
			if (area === "countries" && operation === "add") {
				return "Added " + (String(action.entries || "").trim().split(/\s+/).length === 1
					? "country" : "countries");
			}
			if (area === "countries" && operation === "remove") {
				return "Removed " + (String(action.entries || "").trim().split(/\s+/).length === 1
					? "country" : "countries");
			}
			if (area === "countries" && operation === "refresh") return "Refreshed country sources";
			if (area === "countries") return "Updated country selection";
			if (area === "iot") return "Updated IoT isolation";
			if (area === "settings") return "Updated Skynet settings";
			if (area === "system" && operation === "restore") return "Restored Skynet backup";
			return [operation, target, type].filter(Boolean).join(" ");
		};

        SkynetUI.renderRuleOverview = function() {
            const health = this.getElement(this.selectors.ruleHealth);
            const activity = this.getElement(this.selectors.ruleActivity);
            const summary = window.SkynetRuleSummary || {};
			const actions = Array.isArray(window.SkynetActions)
				? window.SkynetActions.slice().reverse().slice(0, 8)
                : [];

            if (health) {
                health.textContent = "";
				const healthTotal = Number(summary.domains || 0);
                if (!summary.available) {
                    health.textContent = "Rule health is not currently available.";
                } else if (!healthTotal) {
                    health.textContent = "No dynamic domain rules are configured.";
                } else {
                    const label = document.createElement("span");
                    label.textContent = "Domain health";
                    health.appendChild(label);
					["current", "cached", "pending", "empty", "expired", "failed"].forEach(function(state) {
                        const count = Number(summary[state] || 0);
                        if (!count) return;
                        const pill = document.createElement("span");
                        pill.className = "skynet-feed-pill " + state;
						pill.textContent = count.toLocaleString() + " " + SkynetUI.formatRuleState(state);
                        health.appendChild(pill);
                    });
                    const checked = document.createElement("span");
                    checked.className = "skynet-rule-health-time";
					checked.textContent = Number(summary.lastCheck)
						? "Checked " + SkynetUI.formatRelativeTime(summary.lastCheck)
                        : "Not checked yet";
					checked.title = Number(summary.lastCheck)
						? new Date(Number(summary.lastCheck) * 1000).toLocaleString() : "";
                    health.appendChild(checked);
                }
            }

            if (!activity) return;
            activity.textContent = "";
            if (!actions.length) {
                const empty = document.createElement("div");
                empty.className = "skynet-feed-empty";
                empty.textContent = "No actions have been recorded yet.";
                activity.appendChild(empty);
                return;
            }
            actions.forEach(function(action) {
                const row = document.createElement("div");
                const time = document.createElement("span");
                const result = document.createElement("span");
                const summaryText = document.createElement("span");
                const detail = document.createElement("span");
                let entries = String(action.entries || "");
                const extra = String(action.detail || "");
				const countryEntries = entries.split(/\s+/).filter(Boolean);

				if (String(action.area || "") === "countries" && countryEntries.length &&
					countryEntries.every(function(code) { return /^[a-z]{2}$/i.test(code); })) {
					entries = countryEntries.map(function(code) {
						return SkynetUI.getCountryName(code) + " (" + code.toUpperCase() + ")";
					}).join(", ");
				}

                row.className = "skynet-action-row";
                time.className = "skynet-action-time";
				time.textContent = Number(action.epoch)
					? SkynetUI.formatRelativeTime(action.epoch)
                    : String(action.time || "Unknown");
				time.title = [String(action.origin || ""), Number(action.epoch)
					? new Date(Number(action.epoch) * 1000).toLocaleString()
					: String(action.time || "")].filter(Boolean).join(" | ");
                result.className = "skynet-action-result " + action.result;
                result.textContent = String(action.result || "unknown")
                    .replace(/^./, function(value) { return value.toUpperCase(); });
                summaryText.className = "skynet-action-summary";
				summaryText.textContent = SkynetUI.formatActionLabel(action);
                summaryText.title = summaryText.textContent;
                detail.className = "skynet-action-detail";
				detail.textContent = [entries, extra].filter(Boolean).join(" — ");
                detail.title = detail.textContent;
                row.appendChild(time);
                row.appendChild(result);
                row.appendChild(summaryText);
                row.appendChild(detail);
                activity.appendChild(row);
            });
        };

        SkynetUI.populateRules = function() {
            this.ruleEntries = [];
            this.ruleConfirm = "";
            this.renderRuleTags();
            this.renderRules();
            this.renderRuleOverview();
        };

        SkynetUI.submitRule = function(operation, rule) {
            if (this.refreshInProgress || !this.canManageRules()) return;
            const action = rule ? rule.action : this.getElement(this.selectors.ruleAction).value;
            const mode = rule ? rule.type : this.getElement(this.selectors.ruleMode).value;
            const entries = rule ? rule.entry : this.ruleEntries.join(" ");
            const comment = rule || mode !== "ip" || action === "unban"
                ? ""
                : this.getElement(this.selectors.ruleComment).value.trim();
			if (!entries) {
				this.setUpdateResult("Add at least one rule entry.", true, this.selectors.ruleResult);
				return;
			}
			if (comment.length > 242 || /[\r\n\t\x00-\x1f\x7f"]/g.test(comment)) {
				this.setUpdateResult("Enter a valid comment of up to 242 characters.", true, this.selectors.ruleResult);
                return;
            }
            custom_settings.skynet_ruleoperation = operation;
            custom_settings.skynet_ruleaction = action;
            custom_settings.skynet_rulemode = rule
                ? (rule.kind === "manual" || rule.kind === "import" ? rule.kind : rule.type)
                : mode;
            custom_settings.skynet_ruleentries = entries;
            custom_settings.skynet_rulecomment = comment;
            custom_settings.skynet_ruletarget = rule ? rule.target : "";
            custom_settings.skynet_rulesavedcomment = rule ? rule.comment : "";
            custom_settings.skynet_rulerequest = String(new Date().getTime());
            this.refreshInProgress = true;
            const removing = operation === "remove" || action === "unban";
            this.setUpdateResult(removing ? "Removing rule..." : "Applying rule...", false, this.selectors.ruleResult);
            this.setActionState(true, this.selectors.ruleButton, removing ? "Removing..." : "Applying...");
            document.form.amng_custom.value = JSON.stringify(custom_settings);
            this.submitBackgroundAction("start_SkynetRules");
            this.waitForUpdate(window.SkynetSettingsGenerated, 600, "rules");
        };

        SkynetUI.removeRule = function(index, key) {
            const rules = Array.isArray(window.SkynetRules) ? window.SkynetRules : [];
            const rule = rules[index];
            if (!rule) return;
            if (rule.kind === "import" && this.ruleConfirm !== key) {
                this.ruleConfirm = key;
                this.setUpdateResult("Confirm removal of the complete imported group.", false, this.selectors.ruleResult, true);
                this.renderRules();
                return;
            }
            this.ruleConfirm = "";
            this.submitRule("remove", rule);
        };

        SkynetUI.refreshRules = function() {
            if (this.refreshInProgress || !this.canRefreshRules()) return;
            custom_settings.skynet_ruleoperation = "refresh";
            custom_settings.skynet_ruleaction = "all";
            custom_settings.skynet_rulemode = "logical";
            custom_settings.skynet_ruleentries = "registered rules";
            custom_settings.skynet_rulecomment = "";
            custom_settings.skynet_ruletarget = "";
            custom_settings.skynet_rulesavedcomment = "";
            custom_settings.skynet_rulerequest = String(new Date().getTime());
            this.refreshInProgress = true;
            this.setUpdateResult("Refreshing dynamic rules...", false, this.selectors.ruleResult);
            this.setActionState(true, this.selectors.ruleRefresh, "Refreshing...");
            document.form.amng_custom.value = JSON.stringify(custom_settings);
            this.submitBackgroundAction("start_SkynetRules");
            this.waitForUpdate(window.SkynetSettingsGenerated, 600, "ruleRefresh");
        };

        SkynetUI.isIPv4Range = function(value) {
            /*
             * Validate four decimal octets and an optional /0-/32 prefix.
             * The backend repeats validation before touching the live IPSet.
             */
            const parts = String(value || "").split("/");
            const octets = parts[0].split(".");

            if (parts.length > 2 || octets.length !== 4 ||
                !octets.every(function(octet) {
                    return /^\d{1,3}$/.test(octet) && Number(octet) <= 255;
                })) {
                return false;
            }

            return parts.length === 1 ||
                (/^\d{1,2}$/.test(parts[1]) && Number(parts[1]) <= 32);
        };

        SkynetUI.normaliseIOTEntries = function(value) {
            /* Accept legacy commas for display, but keep unique sorted values. */
            const entries = [];

            String(value || "").split(/[\s,]+/).forEach(function(entry) {
                if (SkynetUI.isIPv4Range(entry) && entries.indexOf(entry) === -1) {
                    entries.push(entry);
                }
            });

            return entries.sort();
        };

        SkynetUI.normaliseIOTPorts = function(value) {
            /* Normalise numeric spelling so values such as 080 and 80 de-duplicate. */
            const ports = [];
            const input = String(value || "").trim();

            if (!input) {
                return ports;
            }
            input.split(/[\s,]+/).forEach(function(port) {
                if (!/^\d{1,5}$/.test(port) || Number(port) < 1 ||
                    Number(port) > 65535) {
                    ports.invalid = true;
                } else if (ports.indexOf(String(Number(port))) === -1) {
                    ports.push(String(Number(port)));
                }
            });

            return ports;
        };

        SkynetUI.canManageIOT = function() {
            const settings = window.SkynetSettings;

            return Boolean(settings && window.SkynetSettingsGenerated &&
                Array.isArray(window.SkynetIOTDevices) &&
                Object.prototype.hasOwnProperty.call(settings, "iotentries"));
        };

        SkynetUI.getIOTOptions = function() {
            return this.getIOTPortMode() + "|" +
                this.iotPortSelection.join(" ") + "|" +
                (this.getElement("skynetIotProtocol") || {}).value + "|" +
                (this.getElement("skynetIotBlocking") || {}).value + "|" +
                (this.getElement("skynetIotLogging") || {}).value;
        };

        SkynetUI.getIOTPortMode = function() {
            return (this.getElement(this.selectors.iotPortMode) || {}).value || "default";
        };

        SkynetUI.getIOTPortValue = function() {
            const mode = this.getIOTPortMode();

            if (mode === "none") {
                return "none";
            }
            return mode === "custom" ? this.iotPortSelection.join(" ") : "";
        };

        SkynetUI.isIOTDirty = function() {
            return this.iotSelection.join(" ") !== this.iotOriginal ||
                this.getIOTOptions() !== this.iotOptionsOriginal;
        };

        SkynetUI.findIOTDevice = function(ip) {
            return (window.SkynetIOTDevices || []).find(function(device) {
                return device.ip === ip;
            }) || null;
        };

        SkynetUI.populateIOTPicker = function() {
            const picker = this.getElement(this.selectors.iotPicker);

            if (!picker) {
                return;
            }
            while (picker.firstChild) {
                picker.removeChild(picker.firstChild);
            }
            const placeholder = document.createElement("option");
            placeholder.value = "";
            placeholder.textContent = "Add a detected client...";
            picker.appendChild(placeholder);

            (window.SkynetIOTDevices || []).filter(function(device) {
                return device.ip.indexOf("/") === -1 &&
                    SkynetUI.iotSelection.indexOf(device.ip) === -1;
            }).sort(function(first, second) {
                return String(first.name || first.ip).localeCompare(
                    String(second.name || second.ip)
                );
            }).forEach(function(device) {
                const option = document.createElement("option");
                const name = device.name && device.name !== "Unknown"
                    ? device.name + " — "
                    : "";
                const mac = device.mac && device.mac !== "Unknown"
                    ? " — " + device.mac
                    : "";

                option.value = device.ip;
                option.textContent = name + device.ip + mac;
                picker.appendChild(option);
            });
            picker.value = "";
        };

        SkynetUI.updateIOTControls = function() {
            const supported = this.canManageIOT();
            const busy = this.refreshInProgress;
            const apply = this.getElement(this.selectors.iotButton);
            const clear = this.getElement(this.selectors.iotClear);
            const picker = this.getElement(this.selectors.iotPicker);
            const manual = this.getElement(this.selectors.iotManual);
            const add = this.getElement(this.selectors.iotManualButton);
            const portMode = this.getElement(this.selectors.iotPortMode);
            const portInput = this.getElement(this.selectors.iotPortInput);
            const portAdd = this.getElement(this.selectors.iotPortButton);
            const protocol = this.getElement("skynetIotProtocol");
            const blocking = this.getElement("skynetIotBlocking");
            const logging = this.getElement("skynetIotLogging");
            const customPorts = this.getIOTPortMode() === "custom";
            const validPorts = !customPorts || this.iotPortSelection.length > 0;

            if (apply) apply.disabled = busy || !supported || !validPorts || !this.isIOTDirty();
            if (clear) clear.disabled = busy || !supported || !this.iotSelection.length;
            if (picker) picker.disabled = busy || !supported;
            if (manual) manual.disabled = busy || !supported;
            if (add) add.disabled = busy || !supported;
            if (portMode) portMode.disabled = busy || !supported;
            if (portInput) portInput.disabled = busy || !supported || !customPorts || this.iotPortSelection.length >= 15;
            if (portAdd) portAdd.disabled = busy || !supported || !customPorts || this.iotPortSelection.length >= 15;
            if (protocol) protocol.disabled = busy || !supported || !customPorts;
            if (blocking) blocking.disabled = busy || !supported;
            if (logging) logging.disabled = busy || !supported;
            document.querySelectorAll(".skynet-iot-remove").forEach(function(button) {
                button.disabled = busy || !supported;
            });
            document.querySelectorAll(".skynet-iot-port-remove").forEach(function(button) {
                button.disabled = busy || !supported || !customPorts;
            });
        };

        SkynetUI.renderIOT = function() {
            const list = this.getElement(this.selectors.iotList);

            if (!list) {
                return;
            }
            while (list.firstChild) {
                list.removeChild(list.firstChild);
            }
            if (!this.iotSelection.length) {
                const empty = document.createElement("span");
                empty.className = "skynet-country-empty";
                empty.textContent = "No devices are saved in the IoT list.";
                list.appendChild(empty);
            } else {
                this.iotSelection.forEach(function(ip) {
                    const device = SkynetUI.findIOTDevice(ip) || {};
                    const tag = document.createElement("span");
                    const main = document.createElement("span");
                    const meta = document.createElement("span");
                    const remove = document.createElement("button");

                    tag.className = "skynet-country-tag";
                    main.className = "skynet-iot-tag-main";
                    main.textContent = device.name && device.name !== "Unknown"
                        ? device.name
                        : ip;
                    meta.className = "skynet-iot-tag-meta";
                    meta.textContent = main.textContent === ip
                        ? (device.state || "saved")
                        : ip + " · " + (device.state || "saved");
                    remove.type = "button";
                    remove.className = "skynet-country-remove skynet-iot-remove";
                    remove.dataset.iot = ip;
                    remove.title = "Remove " + ip;
                    remove.setAttribute("aria-label", remove.title);
                    remove.textContent = "×";
                    tag.appendChild(main);
                    tag.appendChild(meta);
                    tag.appendChild(remove);
                    list.appendChild(tag);
                });
            }
            this.setUpdateResult(
                this.isIOTDirty()
                    ? "Unsaved IoT isolation changes."
                    : (this.iotSelection.length
                        ? this.iotSelection.length +
                            (this.iotSelection.length === 1 ? " device saved." : " devices saved.")
                        : ""),
                false,
                this.selectors.iotResult
            );
            this.updateIOTControls();
        };

        SkynetUI.renderIOTPorts = function() {
            const list = this.getElement(this.selectors.iotPortList);

            if (!list) {
                return;
            }
            while (list.firstChild) {
                list.removeChild(list.firstChild);
            }
            const mode = this.getIOTPortMode();

            if (mode !== "custom" || !this.iotPortSelection.length) {
                const empty = document.createElement("span");
                empty.className = "skynet-country-empty";
                if (mode === "none") {
                    empty.textContent = "No TCP or UDP WAN ports are allowed.";
                } else if (mode === "custom") {
                    empty.textContent = "Add at least one custom port.";
                } else {
                    empty.textContent = "UDP/123 is allowed for NTP time synchronization.";
                }
                list.appendChild(empty);
            } else {
                this.iotPortSelection.forEach(function(port) {
                    const tag = document.createElement("span");
                    const value = document.createElement("span");
                    const remove = document.createElement("button");

                    tag.className = "skynet-country-tag";
                    value.textContent = "Port " + port;
                    remove.type = "button";
                    remove.className = "skynet-country-remove skynet-iot-port-remove";
                    remove.dataset.port = port;
                    remove.title = "Remove port " + port;
                    remove.setAttribute("aria-label", remove.title);
                    remove.textContent = "×";
                    tag.appendChild(value);
                    tag.appendChild(remove);
                    list.appendChild(tag);
                });
            }
            this.updateIOTControls();
        };

        SkynetUI.populateIOT = function() {
            const settings = window.SkynetSettings || {};

            if (!this.canManageIOT()) {
                this.iotSelection = [];
                this.iotPortSelection = [];
                this.iotOriginal = "";
                this.iotOptionsOriginal = "";
                this.populateIOTPicker();
                this.renderIOT();
                this.renderIOTPorts();
                return;
            }
            this.iotSelection = this.normaliseIOTEntries(settings.iotentries);
            this.iotPortSelection = settings.iotports === "none"
                ? []
                : this.normaliseIOTPorts(settings.iotports);
            this.iotOriginal = this.iotSelection.join(" ");
            this.getElement(this.selectors.iotPortMode).value = settings.iotports === "none"
                ? "none"
                : (this.iotPortSelection.length ? "custom" : "default");
            this.getElement("skynetIotProtocol").value = settings.iotproto || "udp";
            this.iotOptionsOriginal = this.getIOTOptions();
            this.populateIOTPicker();
            this.renderIOT();
            this.renderIOTPorts();
        };

        SkynetUI.addIOT = function(value) {
            value = String(value || "").trim();
            if (!this.isIPv4Range(value)) {
                this.setUpdateResult(
                    "Enter a valid IPv4 address or CIDR range.",
                    true,
                    this.selectors.iotResult
                );
                return;
            }
            if (this.iotSelection.indexOf(value) === -1) {
                this.iotSelection.push(value);
                this.iotSelection.sort();
            }
            const manual = this.getElement(this.selectors.iotManual);
            if (manual) manual.value = "";
            this.populateIOTPicker();
            this.renderIOT();
        };

        SkynetUI.removeIOT = function(value) {
            const index = this.iotSelection.indexOf(value);
            if (index !== -1 && !this.refreshInProgress) {
                this.iotSelection.splice(index, 1);
                this.populateIOTPicker();
                this.renderIOT();
            }
        };

        SkynetUI.addIOTPort = function(value) {
            const ports = this.normaliseIOTPorts(value);

            if (ports.invalid || ports.length !== 1) {
                this.setUpdateResult(
                    "Enter one port between 1 and 65535.",
                    true,
                    this.selectors.iotResult
                );
                return;
            }
            if (this.iotPortSelection.indexOf(ports[0]) === -1) {
                if (this.iotPortSelection.length >= 15) {
                    this.setUpdateResult(
                        "A maximum of 15 ports can be configured.",
                        true,
                        this.selectors.iotResult
                    );
                    return;
                }
                this.iotPortSelection.push(ports[0]);
                this.iotPortSelection.sort(function(first, second) {
                    return Number(first) - Number(second);
                });
            }
            this.getElement(this.selectors.iotPortMode).value = "custom";
            const input = this.getElement(this.selectors.iotPortInput);
            if (input) input.value = "";
            this.renderIOTPorts();
            this.renderIOT();
        };

        SkynetUI.removeIOTPort = function(value) {
            const index = this.iotPortSelection.indexOf(value);
            if (index !== -1 && !this.refreshInProgress) {
                this.iotPortSelection.splice(index, 1);
                this.renderIOTPorts();
                this.renderIOT();
            }
        };

        SkynetUI.updateIOT = function() {
            if (this.refreshInProgress || !this.canManageIOT() ||
                (this.getIOTPortMode() === "custom" && !this.iotPortSelection.length) ||
                !this.isIOTDirty()) {
                return;
            }
            custom_settings.skynet_iotentries = this.iotSelection.join(" ");
            custom_settings.skynet_iotports = this.getIOTPortValue();
            custom_settings.skynet_iotproto = this.getIOTPortMode() === "default"
                ? "udp"
                : this.getElement("skynetIotProtocol").value;
            custom_settings.skynet_iotblocked = this.getElement("skynetIotBlocking").value;
            custom_settings.skynet_iotlogging = this.getElement("skynetIotLogging").value;
            this.refreshInProgress = true;
            this.setUpdateResult("Applying IoT isolation...", false, this.selectors.iotResult);
            this.setActionState(true, this.selectors.iotButton, "Applying...");
            document.form.amng_custom.value = JSON.stringify(custom_settings);
            this.submitBackgroundAction("start_SkynetIOT");
            this.waitForUpdate(window.SkynetSettingsGenerated, 600, "iot");
        };

        SkynetUI.populateSettings = function() {
            const settings = window.SkynetSettings || {};
            const apply = this.getElement(this.selectors.settingsButton);
            const malware = this.getElement(this.selectors.malwareButton);
            const fields = {
                skynetAutoUpdate: settings.autoupdate,
                skynetMalwareUpdates: settings.banmalwareupdate,
                skynetMalwareUrl: settings.customlisturl,
                skynetFilterTraffic: settings.filtertraffic,
                skynetUnbanPrivate: settings.unbanprivateip,
                skynetAiProtect: settings.banaiprotect,
                skynetSecureMode: settings.securemode,
                skynetLogInvalid: settings.loginvalid,
                skynetLogSize: settings.logsize,
                skynetExtendedStats: settings.extendedstats,
                skynetCountryLookup: settings.lookupcountry,
                skynetCdnWhitelist: settings.cdnwhitelist,
                skynetIotBlocking: settings.iotblocked,
                skynetIotLogging: settings.iotlogging
            };

            if (!window.SkynetSettings || !window.SkynetSettingsGenerated) {
                if (apply) {
                    apply.disabled = true;
                }
                if (malware) {
                    malware.disabled = true;
                }
                this.populateIOT();
                this.populateCountries();
                this.populateFeeds();
                this.populateRules();
                this.setUpdateResult(
                    "Reload settings to load current values.",
                    false,
                    this.selectors.settingsResult
                );
                return;
            }

            Object.keys(fields).forEach(function(id) {
                const field = SkynetUI.getElement(id);

                if (field && fields[id] !== undefined && fields[id] !== null) {
                    field.value = fields[id];
                }
            });

            this.settingsOriginal = this.getSettingsOptions();

            this.populateMalwareStatus();
            this.populateBlacklistCounts(settings);
            this.populateIOT();
            this.populateCountries();
            this.populateFeeds();
            this.populateRules();

            this.updateSettingsControls();
            if (malware && !this.refreshInProgress) {
                malware.disabled = !this.canUpdateMalware();
            }

            const result = this.getElement(this.selectors.settingsResult);

            if (result && result.textContent === "Reload settings to load current values.") {
                result.textContent = "";
            }
        };

        /*
         * Background actions use Merlin's native service-event form target.
         * The page remains interactive while generated payload timestamps are
         * polled to detect completion.
         */
        SkynetUI.setUpdateResult = function(message, isError, resultSelector, isWarning) {
            const result = this.getElement(resultSelector || this.selectors.updateResult);

            if (!result) {
                return;
            }

            result.textContent = message || "";
            result.classList.toggle("error", Boolean(isError));
            result.classList.toggle("warning", Boolean(isWarning));
        };

        SkynetUI.setActionState = function(active, buttonSelector, label) {
            /*
             * One background worker is allowed at a time. When idle, each
             * control is still gated by support, dirty state and list limits.
             */
            [
                this.selectors.updateButton,
                this.selectors.settingsButton,
                this.selectors.settingsReloadButton,
                this.selectors.settingsDefaultsButton,
                this.selectors.malwareButton,
                this.selectors.feedButton,
                this.selectors.countryButton,
                this.selectors.countryRefresh,
                this.selectors.countryClear,
                this.selectors.ruleButton,
                this.selectors.ruleRefresh,
                this.selectors.ruleAdd,
                this.selectors.iotButton,
                this.selectors.iotClear,
                this.selectors.iotManualButton,
                this.selectors.iotPortButton
            ].forEach(function(id) {
                const button = SkynetUI.getElement(id);

                if (button) {
                    button.disabled = active ||
                        (id === SkynetUI.selectors.settingsButton &&
                            (!window.SkynetSettings || !window.SkynetSettingsGenerated ||
                                !SkynetUI.isSettingsDirty())) ||
                        (id === SkynetUI.selectors.malwareButton &&
                            !SkynetUI.canUpdateMalware()) ||
                        (id === SkynetUI.selectors.feedButton &&
                            (!SkynetUI.canManageFeeds() || !SkynetUI.isFeedDirty())) ||
                        ((id === SkynetUI.selectors.countryButton ||
                            id === SkynetUI.selectors.countryClear) &&
                            !SkynetUI.canManageCountries()) ||
                        (id === SkynetUI.selectors.countryButton &&
                            !SkynetUI.isCountryDirty()) ||
                        (id === SkynetUI.selectors.countryRefresh &&
                            (!SkynetUI.canManageCountries() || !SkynetUI.countrySelection.length ||
                                SkynetUI.isCountryDirty())) ||
                        (id === SkynetUI.selectors.countryClear &&
                            !SkynetUI.countrySelection.length) ||
                        (id === SkynetUI.selectors.ruleButton &&
                            (!SkynetUI.canManageRules() || !SkynetUI.ruleEntries.length)) ||
                        (id === SkynetUI.selectors.ruleRefresh &&
                            !SkynetUI.canRefreshRules()) ||
                        (id === SkynetUI.selectors.ruleAdd &&
                            !SkynetUI.canManageRules()) ||
                        (id === SkynetUI.selectors.iotButton &&
                            (!SkynetUI.canManageIOT() ||
                                (SkynetUI.getIOTPortMode() === "custom" &&
                                    !SkynetUI.iotPortSelection.length) ||
                                !SkynetUI.isIOTDirty())) ||
                        (id === SkynetUI.selectors.iotClear &&
                            (!SkynetUI.canManageIOT() || !SkynetUI.iotSelection.length)) ||
                        (id === SkynetUI.selectors.iotManualButton &&
                            !SkynetUI.canManageIOT()) ||
                        (id === SkynetUI.selectors.iotPortButton &&
                            (!SkynetUI.canManageIOT() ||
                                SkynetUI.getIOTPortMode() !== "custom" ||
                                SkynetUI.iotPortSelection.length >= 15));
                    button.classList.toggle("skynet-update-busy", active && id === buttonSelector);
                }
            });

            const picker = this.getElement(this.selectors.countryPicker);
            if (picker) {
                picker.disabled = active || !this.canManageCountries();
            }
            document.querySelectorAll(".skynet-country-remove:not(.skynet-iot-remove):not(.skynet-iot-port-remove):not(.skynet-rule-tag-remove)").forEach(function(remove) {
                remove.disabled = active || !SkynetUI.canManageCountries();
            });

            [this.selectors.iotPicker, this.selectors.iotManual, this.selectors.iotPortInput].forEach(function(id) {
                const control = SkynetUI.getElement(id);
                if (control) control.disabled = active || !SkynetUI.canManageIOT();
            });
            document.querySelectorAll(".skynet-iot-remove, .skynet-iot-port-remove").forEach(function(remove) {
                remove.disabled = active || !SkynetUI.canManageIOT();
            });
            document.querySelectorAll("#skynetFeedList input[type='checkbox']").forEach(function(toggle) {
                toggle.disabled = active || !SkynetUI.canManageFeeds();
            });
            this.updateRuleControls();

            const button = this.getElement(buttonSelector);

            if (button && label) {
                button.value = label;
            }
            this.updateIOTControls();
            this.updateFeedControls();
        };

        SkynetUI.destroyCharts = function() {
            Object.keys(this.charts).forEach(function(chartName) {
                const chart = SkynetUI.charts[chartName];

                if (chart && typeof chart.destroy === "function") {
                    chart.destroy();
                }
            });

            this.charts = Object.create(null);
            this.chartData = Object.create(null);
        };

        SkynetUI.loadScript = function(file, error) {
            /* Cache-busting is required because Merlin serves generated files aggressively. */
            return new Promise(function(resolve, reject) {
                const script = document.createElement("script");

                script.src = "/ext/skynet/" + file + "?_=" + new Date().getTime();
                script.async = true;
                script.onload = function() {
                    script.parentNode.removeChild(script);
                    resolve();
                };
                script.onerror = function() {
                    script.parentNode.removeChild(script);
                    reject(new Error(error));
                };
                document.head.appendChild(script);
            });
        };

        SkynetUI.loadStatsScript = function() {
            return this.loadScript("stats.js", "Unable to load refreshed statistics");
        };

        SkynetUI.loadSettingsScript = function() {
            return this.loadScript("settings.js", "Unable to load current settings");
        };

        SkynetUI.getCountryUpdateError = function() {
            const result = String(window.SkynetSettingsResult || "error");
            const parts = result.split(":");
            const country = this.getCountryName(parts[1]);

            if (parts[0] === "download" && country) {
                return "Unable to download the " + country + " country list.";
            }
            if (parts[0] === "invalid" && country) {
                return country + " returned no valid IPv4 ranges.";
            }
            if (result === "restore") {
                return "Unable to apply country blocking. Previous bans restored.";
            }
            if (result === "connection") {
                return "Unable to update country blocking. Check the router connection.";
            }

            return "Unable to update country blocking.";
        };

        SkynetUI.getMalwareUpdateError = function() {
            const result = String(window.SkynetSettingsResult || "error");

            if (result.indexOf("failed:") === 0) {
                return "No valid cached copy is available for " +
                    result.substring(7) + ". The existing blacklist was retained.";
            }
            if (result === "filter") {
                return "Unable to load a valid malware filter list.";
            }
            if (result === "apply") {
                return "Unable to apply the new blacklist. Existing entries were retained.";
            }
            return "Unable to update malware lists.";
        };

		SkynetUI.getRuleUpdateError = function() {
			const result = String(window.SkynetSettingsResult || "error");
			if (result === "busy") return "Skynet is busy. Try again when the current task finishes.";
			if (result === "validation") return "The rule request contains invalid or incomplete data.";
			if (result === "resolve") return "Unable to resolve one or more domains. Existing rules were retained.";
			if (result === "source") return "Unable to download or validate one or more ASN ranges.";
			if (result === "conflict") return "A resolved address or range is already owned by another rule.";
			if (result === "stale") return "The selected rule no longer exists. Reloaded rule data is shown.";
			if (result === "save") return "Unable to save the rule. Existing rules were restored.";
			if (result === "apply") return "Unable to apply the rule. Existing rules were retained.";
			return "Unable to update rules.";
		};

		SkynetUI.getIOTUpdateError = function() {
			const result = String(window.SkynetSettingsResult || "error");
			if (result === "validation") return "The IoT request contains an invalid address, port, protocol or switch value.";
			if (result === "apply") return "Unable to apply IoT isolation. Previous settings were restored.";
			return "Unable to update IoT isolation.";
		};

		SkynetUI.populateUpdatedSettings = function(requestType, preserveInput) {
			const settings = window.SkynetSettings || {};
			this.populateBlacklistCounts(settings);
			if (preserveInput) return;
			switch (requestType) {
				case "rules": this.populateRules(); break;
				case "ruleRefresh": this.renderRules(); this.renderRuleOverview(); break;
				case "countries":
				case "countryRefresh": this.populateCountries(); break;
				case "feeds": this.populateFeeds(); this.populateMalwareStatus(); break;
				case "malware": this.populateFeeds(); this.populateMalwareStatus(); break;
				case "iot": this.populateIOT(); this.refreshRenderedStats(); break;
				default: this.populateSettings(); this.refreshRenderedStats();
			}
			/* Rules actions already refresh the shared activity journal. */
			if (requestType !== "rules" && requestType !== "ruleRefresh") {
				this.renderRuleOverview();
			}
		};

        SkynetUI.refreshRenderedStats = function() {
            this.destroyCharts();
            this.renderChartsAndTables();
            this.applyStatsPayload();
            this.bindChartControls();

            Object.keys(this.chartDefinitions).forEach(function(chartName) {
                const definition = SkynetUI.chartDefinitions[chartName];
                SkynetUI.setupChart(chartName, definition.multiLabel ? "true" : "false");
            });

            this.setupCollapsibles();
            this.bindTableDetails();
            this.scheduleChartResize();
        };

        SkynetUI.waitForUpdate = function(previousStamp, attempts, requestType) {
            /* A changed generation stamp proves the requested worker finished. */
            const self = this;
            const action = this.actionDefinitions[requestType] ||
                this.actionDefinitions.stats;
            const button = this.selectors[action.button];
            const result = requestType === "reload" && this.reloadResult
                ? this.reloadResult
                : this.selectors[action.result];
            const loadSettings = action.source === "settings";
            const request = loadSettings
                ? this.loadSettingsScript()
                : this.loadStatsScript();

            request.then(function() {
                const currentStamp = loadSettings
                    ? window.SkynetSettingsGenerated
                    : window.SkynetStatsGenerated;

                if (String(currentStamp || "") !== String(previousStamp || "")) {
                    const ruleRequest = String(custom_settings.skynet_rulerequest || "");
                    const currentRequest = String(window.SkynetSettingsRequest || "");
                    const ruleRequestType = requestType === "rules" ||
                        requestType === "ruleRefresh";
                    if (ruleRequestType && ruleRequest &&
                        currentRequest !== ruleRequest) {
                        if (attempts > 0) {
                            window.setTimeout(function() {
                                self.waitForUpdate(previousStamp, attempts - 1, requestType);
                            }, 1000);
                            return;
                        }
                        self.refreshInProgress = false;
                        self.setUpdateResult(action.timeout, true, result);
                        self.setActionState(false, button, "Try Again");
                        return;
                    }
                    let response = String(window.SkynetSettingsResult || "error");
                    if (requestType === "rules" && response === "ready" &&
                        custom_settings.skynet_ruleaction !== "unban" &&
                        self.isRuleRequestApplied()) {
                        response = "success";
                    }
                    const accepted = action.accepted || ["success"];
                    const acceptedResponse = accepted.some(function(value) {
                        return response === value || response.indexOf(value + ":") === 0;
                    });
                    const failed = action.requireSuccess &&
                        !acceptedResponse;
                    const degraded = response === "degraded" ||
                        response.indexOf("degraded:") === 0;
                    const warning = response === "warning" ||
                        response.indexOf("warning:") === 0;

                    if (loadSettings) {
                        const preserveFailedInput = failed &&
                            (requestType === "countries" || requestType === "countryRefresh" ||
                                requestType === "iot" ||
                                (requestType === "rules" && custom_settings.skynet_ruleoperation === "add"));
						self.populateUpdatedSettings(requestType, preserveFailedInput);
                    } else {
                        self.refreshRenderedStats();
                    }
                    self.refreshInProgress = false;
                    if (failed) {
                        self.setUpdateResult(
							ruleRequestType
								? self.getRuleUpdateError()
								: (requestType === "countries" || requestType === "countryRefresh")
								? self.getCountryUpdateError()
								: requestType === "iot"
									? self.getIOTUpdateError()
                                : ((requestType === "malware" || requestType === "feeds")
                                    ? self.getMalwareUpdateError()
                                    : action.failure),
                            true,
                            result
                        );
						self.setActionState(false, button,
							requestType === "rules" && custom_settings.skynet_ruleoperation === "remove"
								? action.label : "Try Again");
                    } else if (degraded) {
                        let degradedMessage =
                            "Blacklist updated using one or more validated cached sources.";
                        if (requestType === "countries" || requestType === "countryRefresh") {
                            const cachedCountries = response.substring(9).split(",")
                                .filter(Boolean)
                                .map(function(code) {
                                    return SkynetUI.getCountryName(code);
                                });
                            degradedMessage = "Country blocking updated using validated cached data" +
                                (cachedCountries.length
                                    ? " for " + cachedCountries.join(", ") + "."
                                    : ".");
                        } else if (requestType === "ruleRefresh") {
                            degradedMessage = "Dynamic domain rules refreshed using validated cached data.";
                        }
                        self.setUpdateResult(
                            degradedMessage,
                            false,
                            result,
                            true
                        );
                        self.setActionState(false, button, action.label);
                    } else if (warning) {
                        self.setUpdateResult(
                            response === "warning:whitelist"
                                ? "Rule saved, but an existing whitelist takes precedence."
                                : "Rule updated with a warning.",
                            false,
                            result,
                            true
                        );
                        self.setActionState(false, button, action.label);
                    } else {
                        self.setUpdateResult(action.success, false, result);
                        self.setActionState(false, button, action.label);
                    }
                    return;
                }

                if (attempts > 0) {
                    window.setTimeout(function() {
                        self.waitForUpdate(previousStamp, attempts - 1, requestType);
                    }, 1000);
                    return;
                }

                self.refreshInProgress = false;
                self.setUpdateResult(action.timeout, true, result);
				self.setActionState(false, button,
					requestType === "rules" && custom_settings.skynet_ruleoperation === "remove"
						? action.label : "Try Again");
            }).catch(function() {
                if (attempts > 0) {
                    window.setTimeout(function() {
                        self.waitForUpdate(previousStamp, attempts - 1, requestType);
                    }, 1000);
                    return;
                }

                self.refreshInProgress = false;
                self.setUpdateResult(action.loadError, true, result);
				self.setActionState(false, button,
					requestType === "rules" && custom_settings.skynet_ruleoperation === "remove"
						? action.label : "Try Again");
            });
        };

        SkynetUI.updateStats = function() {
            if (this.refreshInProgress) {
                return;
            }

            this.refreshInProgress = true;
            this.setUpdateResult("Generating statistics...", false);
            this.setActionState(true, this.selectors.updateButton, "Refreshing...");
            this.submitBackgroundAction("start_SkynetStats");
            this.waitForUpdate(window.SkynetStatsGenerated, 600, "stats");
        };

        SkynetUI.updateMalware = function() {
            if (this.refreshInProgress || !this.canUpdateMalware()) {
                return;
            }

            this.refreshInProgress = true;
            this.setUpdateResult(
                "Updating malware lists...",
                false,
                this.selectors.settingsResult
            );
            this.setActionState(true, this.selectors.malwareButton, "Updating...");
            this.submitBackgroundAction("start_SkynetBanMalware");
            this.waitForUpdate(window.SkynetSettingsGenerated, 600, "malware");
        };

        SkynetUI.updateFeeds = function() {
            if (this.refreshInProgress || !this.canManageFeeds() ||
                !this.isFeedDirty()) {
                return;
            }

            custom_settings.skynet_feedchange = "1";
            custom_settings.skynet_excludelists = this.feedExclusions.join(" ");
            this.refreshInProgress = true;
            this.setUpdateResult(
                "Applying threat feed selection...",
                false,
                this.selectors.feedStatus
            );
            this.setActionState(true, this.selectors.feedButton, "Applying...");
            document.form.amng_custom.value = JSON.stringify(custom_settings);
            this.submitBackgroundAction("start_SkynetBanMalware");
            this.waitForUpdate(window.SkynetSettingsGenerated, 600, "feeds");
        };

        SkynetUI.updateCountries = function() {
            if (this.refreshInProgress || !this.canManageCountries() ||
                !this.isCountryDirty()) {
                return;
            }

            custom_settings.skynet_countrylist = this.countrySelection.join(" ");
            custom_settings.skynet_countryrefresh = "0";
            this.refreshInProgress = true;
            this.setUpdateResult(
                this.countrySelection.length
                    ? "Updating country blocking..."
                    : "Removing country blocking...",
                false,
                this.selectors.countryResult
            );
            this.setActionState(true, this.selectors.countryButton, "Applying...");
            document.form.amng_custom.value = JSON.stringify(custom_settings);
            this.submitBackgroundAction("start_SkynetCountries");
            this.waitForUpdate(window.SkynetSettingsGenerated, 600, "countries");
        };

        SkynetUI.refreshCountries = function() {
            if (this.refreshInProgress || !this.canManageCountries() ||
                !this.countrySelection.length || this.isCountryDirty()) {
                return;
            }
            custom_settings.skynet_countrylist = this.countrySelection.join(" ");
            custom_settings.skynet_countryrefresh = "1";
            this.refreshInProgress = true;
            this.setUpdateResult("Refreshing country sources...", false, this.selectors.countryResult);
            this.setActionState(true, this.selectors.countryRefresh, "Refreshing...");
            document.form.amng_custom.value = JSON.stringify(custom_settings);
            this.submitBackgroundAction("start_SkynetCountries");
            this.waitForUpdate(window.SkynetSettingsGenerated, 600, "countryRefresh");
        };

        SkynetUI.submitBackgroundAction = function(action) {
            /*
             * action_script is dispatched by Merlin after the hidden form is
             * submitted. Clear amng_custom afterwards to prevent stale edits
             * from being included in a later, unrelated request.
             */
            const settings = this.getElement("amng_custom");

            document.form.action_script.value = action;
            document.form.submit();

            if (settings) {
                settings.value = "";
            }
        };

        SkynetUI.restoreDefaultSettings = function() {
            const defaults = {
                updates: {
                    skynetAutoUpdate: "enabled",
                    skynetMalwareUpdates: "daily",
                    skynetMalwareUrl: ""
                },
                protection: {
                    skynetFilterTraffic: "all",
                    skynetUnbanPrivate: "enabled",
                    skynetAiProtect: "enabled",
                    skynetSecureMode: "enabled",
                    skynetCdnWhitelist: "enabled"
                },
                statistics: {
                    skynetLogInvalid: "disabled",
                    skynetLogSize: "10",
                    skynetExtendedStats: "enabled",
                    skynetCountryLookup: "enabled"
                }
            };
            const sectionDefaults = defaults[this.settingsSection] || {};

            Object.keys(sectionDefaults).forEach(function(id) {
                const field = SkynetUI.getElement(id);

                if (field) {
                    field.value = sectionDefaults[id];
                }
            });

            this.setUpdateResult(
                "Default values loaded for this section. Apply Settings to save.",
                false,
                this.selectors.settingsResult
            );
            this.updateSettingsControls();
        };

        SkynetUI.updateSettings = function() {
            if (this.refreshInProgress || !this.isSettingsDirty()) {
                return;
            }

            const logsize = this.getElement("skynetLogSize").value;
            const customlisturl = this.getElement("skynetMalwareUrl").value.trim();

            if (!/^\d+$/.test(logsize) || Number(logsize) < 10) {
                this.showView("statistics");
                this.setUpdateResult(
                    "Log size must be at least 10MB.",
                    true,
                    this.selectors.settingsResult
                );
                return;
            }

            if (customlisturl &&
                (customlisturl.length > 512 ||
                    !/^https?:\/\/[A-Za-z0-9._~:/?&=#%@+,-]+$/i.test(customlisturl))) {
                this.setUpdateResult(
                    "Enter a valid HTTP(S) filter list URL.",
                    true,
                    this.selectors.settingsResult
                );
                return;
            }

            custom_settings.skynet_autoupdate = this.getElement("skynetAutoUpdate").value;
            custom_settings.skynet_banmalwareupdate = this.getElement("skynetMalwareUpdates").value;
            custom_settings.skynet_customlisturl = customlisturl;
            custom_settings.skynet_filtertraffic = this.getElement("skynetFilterTraffic").value;
            custom_settings.skynet_unbanprivateip = this.getElement("skynetUnbanPrivate").value;
            custom_settings.skynet_banaiprotect = this.getElement("skynetAiProtect").value;
            custom_settings.skynet_securemode = this.getElement("skynetSecureMode").value;
            custom_settings.skynet_loginvalid = this.getElement("skynetLogInvalid").value;
            custom_settings.skynet_logsize = logsize;
            custom_settings.skynet_extendedstats = this.getElement("skynetExtendedStats").value;
            custom_settings.skynet_lookupcountry = this.getElement("skynetCountryLookup").value;
            custom_settings.skynet_cdnwhitelist = this.getElement("skynetCdnWhitelist").value;

            this.refreshInProgress = true;
            this.setUpdateResult("Applying settings...", false, this.selectors.settingsResult);
            this.setActionState(true, this.selectors.settingsButton, "Applying...");
            document.form.amng_custom.value = JSON.stringify(custom_settings);
            this.submitBackgroundAction("start_SkynetSettings");
            this.waitForUpdate(window.SkynetSettingsGenerated, 600, "settings");
        };

        SkynetUI.reloadSettings = function() {
            if (this.refreshInProgress) {
                return;
            }

            this.reloadResult = this.settingsSection === "iot"
                ? this.selectors.iotResult
                : (this.settingsSection === "countries"
                    ? this.selectors.countryResult
                    : (this.settingsSection === "rules"
                        ? this.selectors.ruleResult
                        : this.selectors.settingsResult));
            this.refreshInProgress = true;
            this.setUpdateResult("Reloading current data...", false, this.reloadResult);
            this.setActionState(true, this.selectors.settingsReloadButton, "Reloading...");
            this.submitBackgroundAction("start_SkynetSettingsLoad");
            this.waitForUpdate(window.SkynetSettingsGenerated, 60, "reload");
        };

        /* Page rendering and controls. */
        SkynetUI.setCurrentPage = function() {
            const page = window.location.pathname.substring(1);
            const current = this.getElement("current_page");
            const next = this.getElement("next_page");

            if (current) {
                current.value = page;
            }

            if (next) {
                next.value = page;
            }
        };

        SkynetUI.showSettingsSection = function(section) {
            const sections = ["updates", "protection", "rules", "iot", "countries", "statistics"];

            if (sections.indexOf(section) === -1) {
                section = "updates";
            }

            this.settingsSection = section;
            const actions = document.querySelector(".skynet-settings-actions");

            if (actions) {
                actions.setAttribute("data-active-section", section);
            }
            document.querySelectorAll("[data-settings-section]").forEach(function(row) {
                row.classList.toggle(
                    "skynet-settings-section-hidden",
                    row.getAttribute("data-settings-section") !== section
                );
            });
            document.querySelectorAll("[data-action-sections]").forEach(function(control) {
                const supported = control.getAttribute("data-action-sections")
                    .split(/\s+/);

                control.classList.toggle(
                    "skynet-settings-action-hidden",
                    supported.indexOf(section) === -1
                );
            });
        };

        SkynetUI.initializeSettingsSections = function() {
            const table = document.querySelector(".skynet-settings-table");
            let section = "";

            if (!table) {
                return;
            }

            Array.prototype.forEach.call(table.rows, function(row) {
                if (row.classList.contains("skynet-settings-group")) {
                    section = row.getAttribute("data-settings-section") || "";
                }
                if (section) {
                    row.setAttribute("data-settings-section", section);
                }
            });
            this.showSettingsSection(this.settingsSection);
        };

        SkynetUI.showView = function(view) {
            const settings = view !== "overview";
            const overviewTab = this.getElement(this.selectors.overviewTab);
            const overviewView = this.getElement(this.selectors.overviewView);
            const settingsView = this.getElement(this.selectors.settingsView);

            if (settings) {
                this.showSettingsSection(
                    view === "settings" ? this.settingsSection : view
                );
            }

            if (overviewTab) {
                overviewTab.classList.toggle("active", !settings);
                overviewTab.setAttribute("aria-selected", String(!settings));
            }

            document.querySelectorAll(".skynet-settings-tab").forEach(function(tab) {
                const active = settings &&
                    tab.getAttribute("data-settings-target") === SkynetUI.settingsSection;

                tab.classList.toggle("active", active);
                tab.setAttribute("aria-selected", String(active));
            });

            if (overviewView) {
                overviewView.classList.toggle("skynet-view-hidden", settings);
            }

            if (settingsView) {
                settingsView.classList.toggle("skynet-view-hidden", !settings);
            }

            if (!settings) {
                this.scheduleChartResize();
            }
        };

        SkynetUI.bindChartControls = function() {
            document.querySelectorAll("[id$='_Type']").forEach(function(element) {
                const chartName = element.id.substring(
                    0,
                    element.id.indexOf("_")
                );
                const definition = SkynetUI.chartDefinitions[chartName];
                const multiLabel = definition && definition.multiLabel
                    ? "true"
                    : "false";

                element.addEventListener("change", function() {
                    SkynetUI.changeChart(this, multiLabel);
                });
            });

            document.querySelectorAll("[id$='_Group']").forEach(function(element) {
                const chartName = element.id.substring(
                    0,
                    element.id.indexOf("_")
                );

                element.addEventListener("change", function() {
                    SkynetUI.changeChart(this, "true");
                });
            });
        };

        SkynetUI.bindControls = function() {
            this.bindChartControls();

            const update = this.getElement(this.selectors.updateButton);

            if (update) {
                update.addEventListener("click", function() {
                    SkynetUI.updateStats();
                });
            }

            const malware = this.getElement(this.selectors.malwareButton);

            if (malware) {
                malware.addEventListener("click", function() {
                    SkynetUI.updateMalware();
                });
            }

            const feedApply = this.getElement(this.selectors.feedButton);
            if (feedApply) {
                feedApply.addEventListener("click", function() {
                    SkynetUI.updateFeeds();
                });
            }
            const countryPicker = this.getElement(this.selectors.countryPicker);

            if (countryPicker) {
                countryPicker.addEventListener("change", function() {
                    SkynetUI.addCountry(this.value);
                });
            }

            const countryList = this.getElement(this.selectors.countryHealth);

            if (countryList) {
                countryList.addEventListener("click", function(event) {
                    const button = event.target;

                    if (button.classList.contains("skynet-country-remove")) {
                        SkynetUI.removeCountry(button.dataset.country);
                    }
                });
            }

            const countryClear = this.getElement(this.selectors.countryClear);

            if (countryClear) {
                countryClear.addEventListener("click", function() {
                    SkynetUI.clearCountries();
                });
            }

            const countryApply = this.getElement(this.selectors.countryButton);

            if (countryApply) {
                countryApply.addEventListener("click", function() {
                    SkynetUI.updateCountries();
                });
            }

            const countryRefresh = this.getElement(this.selectors.countryRefresh);
            if (countryRefresh) {
                countryRefresh.addEventListener("click", function() {
                    SkynetUI.refreshCountries();
                });
            }

            const ruleAdd = this.getElement(this.selectors.ruleAdd);
            const ruleInput = this.getElement(this.selectors.ruleInput);
            if (ruleAdd) ruleAdd.addEventListener("click", function() { SkynetUI.addRuleEntries(); });
            if (ruleInput) ruleInput.addEventListener("keydown", function(event) {
                if (event.key === "Enter") {
                    event.preventDefault();
                    SkynetUI.addRuleEntries();
                }
            });
            const ruleTags = this.getElement(this.selectors.ruleTags);
            if (ruleTags) ruleTags.addEventListener("click", function(event) {
                if (event.target.classList.contains("skynet-rule-tag-remove")) {
                    SkynetUI.removeRuleEntry(event.target.dataset.entry);
                }
            });
            const ruleMode = this.getElement(this.selectors.ruleMode);
            if (ruleMode) ruleMode.addEventListener("change", function() {
                SkynetUI.ruleEntries = [];
                SkynetUI.renderRuleTags();
            });
            const ruleAction = this.getElement(this.selectors.ruleAction);
            if (ruleAction) ruleAction.addEventListener("change", function() {
                const comment = SkynetUI.getElement(SkynetUI.selectors.ruleComment);
                if (this.value === "unban" && comment) comment.value = "";
                SkynetUI.updateRuleControls();
            });
            const ruleFilter = this.getElement(this.selectors.ruleFilter);
            if (ruleFilter) ruleFilter.addEventListener("change", function() {
                SkynetUI.ruleFilter = this.value;
                SkynetUI.ruleConfirm = "";
                SkynetUI.renderRules();
            });
            const ruleSearch = this.getElement(this.selectors.ruleSearch);
            if (ruleSearch) ruleSearch.addEventListener("input", function() {
                SkynetUI.ruleConfirm = "";
                SkynetUI.renderRules();
            });
            const ruleList = this.getElement(this.selectors.ruleList);
            if (ruleList) ruleList.addEventListener("click", function(event) {
                if (event.target.classList.contains("skynet-rule-remove")) {
                    SkynetUI.removeRule(Number(event.target.dataset.ruleIndex), event.target.dataset.ruleKey);
                }
            });
            const ruleApply = this.getElement(this.selectors.ruleButton);
            if (ruleApply) ruleApply.addEventListener("click", function() {
                SkynetUI.submitRule("add");
            });
            const ruleRefresh = this.getElement(this.selectors.ruleRefresh);
            if (ruleRefresh) ruleRefresh.addEventListener("click", function() {
                SkynetUI.refreshRules();
            });

            const iotPicker = this.getElement(this.selectors.iotPicker);
            if (iotPicker) {
                iotPicker.addEventListener("change", function() {
                    SkynetUI.addIOT(this.value);
                });
            }
            const iotManual = this.getElement(this.selectors.iotManual);
            const addIOT = function() {
                SkynetUI.addIOT(iotManual ? iotManual.value : "");
            };
            const iotManualButton = this.getElement(this.selectors.iotManualButton);
            if (iotManualButton) iotManualButton.addEventListener("click", addIOT);
            if (iotManual) {
                iotManual.addEventListener("keydown", function(event) {
                    if (event.key === "Enter") {
                        event.preventDefault();
                        addIOT();
                    }
                });
            }
            const iotList = this.getElement(this.selectors.iotList);
            if (iotList) {
                iotList.addEventListener("click", function(event) {
                    if (event.target.classList.contains("skynet-iot-remove")) {
                        SkynetUI.removeIOT(event.target.dataset.iot);
                    }
                });
            }
            const iotClear = this.getElement(this.selectors.iotClear);
            if (iotClear) {
                iotClear.addEventListener("click", function() {
                    SkynetUI.iotSelection = [];
                    SkynetUI.populateIOTPicker();
                    SkynetUI.renderIOT();
                });
            }
            const iotApply = this.getElement(this.selectors.iotButton);
            if (iotApply) iotApply.addEventListener("click", function() { SkynetUI.updateIOT(); });
            const iotPortInput = this.getElement(this.selectors.iotPortInput);
            const addIOTPort = function() {
                SkynetUI.addIOTPort(iotPortInput ? iotPortInput.value : "");
            };
            const iotPortButton = this.getElement(this.selectors.iotPortButton);
            if (iotPortButton) iotPortButton.addEventListener("click", addIOTPort);
            if (iotPortInput) {
                iotPortInput.addEventListener("keydown", function(event) {
                    if (event.key === "Enter") {
                        event.preventDefault();
                        addIOTPort();
                    }
                });
            }
            const iotPortList = this.getElement(this.selectors.iotPortList);
            if (iotPortList) {
                iotPortList.addEventListener("click", function(event) {
                    if (event.target.classList.contains("skynet-iot-port-remove")) {
                        SkynetUI.removeIOTPort(event.target.dataset.port);
                    }
                });
            }
            ["skynetIotPortMode", "skynetIotProtocol", "skynetIotBlocking", "skynetIotLogging"]
                .forEach(function(id) {
                    const control = SkynetUI.getElement(id);
                    if (control) control.addEventListener("change", function() {
                        SkynetUI.renderIOTPorts();
                        SkynetUI.renderIOT();
                    });
                });

            const apply = this.getElement(this.selectors.settingsButton);

            if (apply) {
                apply.addEventListener("click", function() {
                    SkynetUI.updateSettings();
                });
            }

            [
                "skynetAutoUpdate", "skynetMalwareUpdates", "skynetMalwareUrl",
                "skynetFilterTraffic", "skynetUnbanPrivate", "skynetAiProtect",
                "skynetSecureMode", "skynetLogInvalid", "skynetLogSize",
                "skynetExtendedStats", "skynetCountryLookup", "skynetCdnWhitelist"
            ].forEach(function(id) {
                const control = SkynetUI.getElement(id);
                if (!control) return;
                control.addEventListener("change", function() {
                    SkynetUI.updateSettingsControls();
                });
                if (control.tagName === "INPUT") {
                    control.addEventListener("input", function() {
                        SkynetUI.updateSettingsControls();
                    });
                }
            });

            const reload = this.getElement(this.selectors.settingsReloadButton);

            if (reload) {
                reload.addEventListener("click", function() {
                    SkynetUI.reloadSettings();
                });
            }

            const defaults = this.getElement(this.selectors.settingsDefaultsButton);

            if (defaults) {
                defaults.addEventListener("click", function() {
                    SkynetUI.restoreDefaultSettings();
                });
            }

            const overviewTab = this.getElement(this.selectors.overviewTab);

            if (overviewTab) {
                overviewTab.addEventListener("click", function() {
                    SkynetUI.showView("overview");
                });
            }

            document.querySelectorAll(".skynet-settings-tab").forEach(function(tab) {
                tab.addEventListener("click", function() {
                    SkynetUI.showView(this.getAttribute("data-settings-target"));
                });
            });
        };

        SkynetUI.renderChartsAndTables = function() {
            const anchor = this.getElement(this.selectors.statsContent);

            if (!anchor) {
                return false;
            }

            const content = [];

            Object.keys(this.chartDefinitions).forEach(function(chartName) {
                const definition = SkynetUI.chartDefinitions[chartName];

                if (!SkynetUI.isChartEnabled(definition)) {
                    return;
                }

                content.push(definition.activity
                    ? SkynetUI.buildActivityChartHtml(definition.title, chartName)
                    : SkynetUI.buildChartHtml(
                        definition.title,
                        chartName,
                        definition.multiLabel ? "true" : "false"
                    ));
            });

            Object.keys(this.tableDefinitions).forEach(function(tableName) {
                content.push(
                    SkynetUI.buildTableHtml(
                        SkynetUI.tableDefinitions[tableName],
                        tableName
                    )
                );
            });

            anchor.innerHTML = content.join("");

            return true;
        };

        /* Native Asuswrt-Merlin page entry point. */
        function initial() {
            SkynetUI.initialize();
        }

        SkynetUI.initialize = function() {
            show_menu();

            this.initializeTheme();

            if (!this.renderChartsAndTables()) {
                return;
            }

            this.initializeSettingsSections();
            this.bindControls();

            const initialiseCharts = function() {
                Object.keys(SkynetUI.chartDefinitions).forEach(function(chartName) {
                    const definition = SkynetUI.chartDefinitions[chartName];
                    const section = SkynetUI.getElement("skynet_chart_" + chartName);

                    /* Collapsed charts are created only when the user opens them. */
                    if (!section || !section.classList.contains("expanded")) {
                        return;
                    }

                    SkynetUI.setupChart(
                        chartName,
                        definition.multiLabel ? "true" : "false"
                    );
                });

                SkynetUI.scheduleChartResize();
            };

            if (typeof window.requestAnimationFrame === "function") {
                window.requestAnimationFrame(function() {
                    window.requestAnimationFrame(initialiseCharts);
                });
            } else {
                window.setTimeout(initialiseCharts, 50);
            }

            this.setupCollapsibles();
            this.bindTableDetails();

            const detailClose = this.getElement("skynetDetailClose");
            if (detailClose) {
                detailClose.addEventListener("click", function() {
                    SkynetUI.closeDetails();
                });
            }

            this.setCurrentPage();

            if (!this.chartResizeBound) {
                this.chartResizeBound = true;

                const resizeHandler = function() {
                    SkynetUI.scheduleChartResize();
                };

                window.addEventListener("resize", resizeHandler, false);
                window.addEventListener("orientationchange", resizeHandler, false);
            }

            this.applyStatsPayload();
            this.populateSettings();
        };
    </script>
</head>

<body onload="initial();">
    <div id="TopBanner"></div>
    <div id="Loading" class="popup_bg"></div>
    <iframe name="hidden_frame" id="hidden_frame" src="about:blank" width="0" height="0" frameborder="0"></iframe>
    <form method="post" name="form" id="ruleForm" action="/start_apply.htm" target="hidden_frame">
        <input type="hidden" name="action_script" value="start_SkynetStats" />
        <input type="hidden" name="current_page" id="current_page" value="" />
        <input type="hidden" name="next_page" id="next_page" value="" />
        <input type="hidden" name="modified" value="0" />
        <input type="hidden" name="action_mode" value="apply" />
        <input type="hidden" name="action_wait" value="45" />
        <input type="hidden" name="flag" value="background" />
        <input type="hidden" name="amng_custom" id="amng_custom" value="" />
        <input type="hidden" name="first_time" value="" />
        <input type="hidden" name="SystemCmd" value="" />
        <input type="hidden" name="preferred_lang" id="preferred_lang" value="<% nvram_get( preferred_lang ); %>" />
        <input type="hidden" name="firmver" value="<% nvram_get( firmver ); %>" />
        <table class="content" align="center" cellpadding="0" cellspacing="0">
            <tr>
                <td width="17">&nbsp;</td>
                <td valign="top" width="202">
                    <div id="mainMenu"></div>
                    <div id="subMenu"></div>
                </td>
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

                                                <div class="skynet-tabs" role="tablist" aria-label="Skynet views">
                                                    <input type="button"
                                                        id="skynetOverviewTab"
                                                        value="Overview"
                                                        class="skynet-tab active"
                                                        role="tab"
                                                        aria-controls="skynetOverviewView"
                                                        aria-selected="true" />
                                                    <input type="button"
                                                        id="skynetUpdatesTab"
                                                        value="Updates"
                                                        class="skynet-tab skynet-settings-tab"
                                                        data-settings-target="updates"
                                                        role="tab"
                                                        aria-controls="skynetSettingsView"
                                                        aria-selected="false" />
                                                    <input type="button"
                                                        id="skynetProtectionTab"
                                                        value="Protection"
                                                        class="skynet-tab skynet-settings-tab"
                                                        data-settings-target="protection"
                                                        role="tab"
                                                        aria-controls="skynetSettingsView"
                                                        aria-selected="false" />
                                                    <input type="button"
                                                        id="skynetRulesTab"
                                                        value="Rules"
                                                        class="skynet-tab skynet-settings-tab"
                                                        data-settings-target="rules"
                                                        role="tab"
                                                        aria-controls="skynetSettingsView"
                                                        aria-selected="false" />
                                                    <input type="button"
                                                        id="skynetIotTab"
                                                        value="IoT"
                                                        class="skynet-tab skynet-settings-tab"
                                                        data-settings-target="iot"
                                                        role="tab"
                                                        aria-controls="skynetSettingsView"
                                                        aria-selected="false" />
                                                    <input type="button"
                                                        id="skynetCountriesTab"
                                                        value="Countries"
                                                        class="skynet-tab skynet-settings-tab"
                                                        data-settings-target="countries"
                                                        role="tab"
                                                        aria-controls="skynetSettingsView"
                                                        aria-selected="false" />
                                                    <input type="button"
                                                        id="skynetStatisticsTab"
                                                        value="Statistics"
                                                        class="skynet-tab skynet-settings-tab"
                                                        data-settings-target="statistics"
                                                        role="tab"
                                                        aria-controls="skynetSettingsView"
                                                        aria-selected="false" />
                                                </div>

                                                <div id="skynetSettingsView" class="skynet-view-hidden" role="tabpanel">
                                                    <div class="skynet-settings">
                                                        <table class="FormTable skynet-settings-table">
                                                            <tr class="skynet-settings-group" data-settings-section="updates">
                                                                <th colspan="2">Updates &amp; Lists</th>
                                                            </tr>
                                                            <tr>
                                                                <th>
                                                                    <span class="skynet-setting-name">Automatic Updates</span>
                                                                    <span class="skynet-setting-help">Installs Skynet updates weekly.</span>
                                                                </th>
                                                                <td>
                                                                    <select class="input_option" id="skynetAutoUpdate">
                                                                        <option value="enabled">Enabled (Default)</option>
                                                                        <option value="disabled">Disabled</option>
                                                                    </select>
                                                                </td>
                                                            </tr>
                                                            <tr>
                                                                <th>
                                                                    <span class="skynet-setting-name">Malware List Updates</span>
                                                                    <span class="skynet-setting-help">Refreshes the malware blacklist on schedule.</span>
                                                                </th>
                                                                <td>
                                                                    <div class="skynet-malware-controls">
                                                                        <select class="input_option" id="skynetMalwareUpdates">
                                                                            <option value="daily">Daily (Default)</option>
                                                                            <option value="weekly">Weekly</option>
                                                                            <option value="disabled">Disabled</option>
                                                                        </select>
                                                                        <input type="button"
                                                                            id="skynetUpdateMalware"
                                                                            value="Update Now"
                                                                            class="button_gen skynet-update-button skynet-malware-update"
                                                                            disabled="disabled" />
                                                                    </div>
                                                                    <span class="skynet-malware-status" id="skynetMalwareStatus">Loading malware list status...</span>
                                                                </td>
                                                            </tr>
                                                            <tr>
                                                                <th>
                                                                    <span class="skynet-setting-name">Malware Filter List</span>
                                                                    <span class="skynet-setting-help">Leave blank to use Skynet's default filter list. Applying a change rebuilds the malware blacklist.</span>
                                                                </th>
                                                                <td>
                                                                    <input type="url"
                                                                        id="skynetMalwareUrl"
                                                                        maxlength="512"
                                                                        placeholder="Default Skynet filter list"
                                                                        autocomplete="off"
                                                                        autocorrect="off"
                                                                        autocapitalize="off"
                                                                        spellcheck="false" />
                                                                </td>
                                                            </tr>
                                                            <tr class="skynet-feed-container">
                                                                <td colspan="2">
                                                                    <div class="skynet-feed-manager">
                                                                        <div class="skynet-feed-intro">
                                                                            <span class="skynet-feed-title">Threat Feed Sources</span>
                                                                            <span class="skynet-feed-help">Choose which trusted sources build the malware blacklist.</span>
                                                                        </div>
                                                                        <div class="skynet-feed-header" id="skynetFeedHeader">
                                                                            <span>Source</span>
                                                                            <span>Entries</span>
                                                                            <span>Last Success / Change</span>
                                                                            <span>State</span>
                                                                            <span>Enabled</span>
                                                                        </div>
                                                                        <div id="skynetFeedList">
                                                                            <div class="skynet-feed-empty">Loading threat feed details...</div>
                                                                        </div>
                                                                        <div class="skynet-feed-actions">
                                                                            <span class="skynet-feed-status" id="skynetFeedStatus" aria-live="polite"></span>
                                                                            <input type="button"
                                                                                id="skynetApplyFeeds"
                                                                                value="Apply Sources"
                                                                                class="button_gen skynet-update-button"
                                                                                disabled="disabled" />
                                                                        </div>
                                                                    </div>
                                                                </td>
                                                            </tr>
                                                            <tr class="skynet-settings-group" data-settings-section="protection">
                                                                <th colspan="2">Protection</th>
                                                            </tr>
                                                            <tr>
                                                                <th>
                                                                    <span class="skynet-setting-name">Traffic Filtering</span>
                                                                    <span class="skynet-setting-help">Selects which traffic directions Skynet blocks.</span>
                                                                </th>
                                                                <td>
                                                                    <select class="input_option" id="skynetFilterTraffic">
                                                                        <option value="all">Inbound &amp; Outbound (Default)</option>
                                                                        <option value="inbound">Inbound Only</option>
                                                                        <option value="outbound">Outbound Only</option>
                                                                    </select>
                                                                </td>
                                                            </tr>
                                                            <tr>
                                                                <th>
                                                                    <span class="skynet-setting-name">Unban Private IPs</span>
                                                                    <span class="skynet-setting-help">Removes and whitelists private addresses found in blocked traffic.</span>
                                                                </th>
                                                                <td>
                                                                    <select class="input_option" id="skynetUnbanPrivate">
                                                                        <option value="enabled">Enabled (Default)</option>
                                                                        <option value="disabled">Disabled</option>
                                                                    </select>
                                                                </td>
                                                            </tr>
                                                            <tr>
                                                                <th>
                                                                    <span class="skynet-setting-name">Import AiProtection Bans</span>
                                                                    <span class="skynet-setting-help">Imports threats blocked by AiProtection into Skynet.</span>
                                                                </th>
                                                                <td>
                                                                    <select class="input_option" id="skynetAiProtect">
                                                                        <option value="enabled">Enabled (Default)</option>
                                                                        <option value="disabled">Disabled</option>
                                                                    </select>
                                                                </td>
                                                            </tr>
                                                            <tr>
                                                                <th>
                                                                    <span class="skynet-setting-name">Secure Mode</span>
                                                                    <span class="skynet-setting-help">Disables WAN access to SSH and the router WebUI.</span>
                                                                </th>
                                                                <td>
                                                                    <select class="input_option" id="skynetSecureMode">
                                                                        <option value="enabled">Enabled (Default)</option>
                                                                        <option value="disabled">Disabled</option>
                                                                    </select>
                                                                </td>
                                                            </tr>
                                                            <tr>
                                                                <th>
                                                                    <span class="skynet-setting-name">CDN Whitelisting</span>
                                                                    <span class="skynet-setting-help">Whitelists common CDN address ranges to reduce false positives.</span>
                                                                </th>
                                                                <td>
                                                                    <select class="input_option" id="skynetCdnWhitelist">
                                                                        <option value="enabled">Enabled (Default)</option>
                                                                        <option value="disabled">Disabled</option>
                                                                    </select>
                                                                </td>
                                                            </tr>
                                                            <tr class="skynet-settings-group" data-settings-section="rules">
                                                                <th colspan="2">Rules Manager</th>
                                                            </tr>
                                                            <tr class="skynet-rules-container">
                                                                <td colspan="2">
                                                                    <div class="skynet-rules-manager">
                                                                        <div class="skynet-feed-intro">
                                                                            <span class="skynet-feed-title">Manual Firewall Rules</span>
                                                                            <span class="skynet-feed-help">Ban, unban or whitelist direct entries, review imported groups and remove saved rules.</span>
                                                                        </div>
                                                                        <div class="skynet-rule-overview">
                                                                            <div class="skynet-rule-health" id="skynetRuleHealth">Loading domain health...</div>
                                                                            <input type="button"
                                                                                id="skynetRefreshRules"
                                                                                value="Refresh Dynamic Rules"
                                                                                class="button_gen skynet-update-button skynet-settings-reload" />
                                                                        </div>
                                                                        <div class="skynet-rules-toolbar">
                                                                            <label class="skynet-rule-field">
                                                                                <span class="skynet-rule-label">Action</span>
                                                                                <select class="input_option" id="skynetRuleAction">
                                                                                    <option value="ban">Ban</option>
                                                                                    <option value="unban">Unban</option>
                                                                                    <option value="whitelist">Whitelist</option>
                                                                                </select>
                                                                            </label>
                                                                            <label class="skynet-rule-field">
                                                                                <span class="skynet-rule-label">Rule Type</span>
                                                                                <select class="input_option" id="skynetRuleMode">
                                                                                    <option value="ip">IPv4 / CIDR</option>
                                                                                    <option value="domain">Domain</option>
                                                                                    <option value="asn">ASN</option>
                                                                                </select>
                                                                            </label>
                                                                            <label class="skynet-rule-field skynet-rule-field-entries">
                                                                                <span class="skynet-rule-label">Entries</span>
                                                                                <input type="text"
                                                                                    id="skynetRuleInput"
                                                                                    maxlength="1024"
                                                                                    placeholder="Separate multiple entries with spaces"
                                                                                    autocomplete="off"
                                                                                    spellcheck="false" />
                                                                            </label>
                                                                            <input type="button"
                                                                                id="skynetAddRuleEntry"
                                                                                value="Add"
                                                                                class="button_gen skynet-update-button skynet-settings-reload" />
                                                                            <label class="skynet-rule-field skynet-rule-field-entries">
                                                                                <span class="skynet-rule-label">Comment</span>
                                                                                <input type="text"
                                                                                    id="skynetRuleComment"
                                                                                    maxlength="242"
                                                                                    placeholder="Optional comment"
                                                                                    autocomplete="off" />
                                                                            </label>
                                                                        </div>
                                                                        <div class="skynet-rule-tags" id="skynetRuleTags">
                                                                            <span class="skynet-country-empty">Add one or more entries to stage a rule.</span>
                                                                        </div>
                                                                        <div class="skynet-rules-filterbar">
                                                                            <select class="input_option skynet-rule-filter" id="skynetRuleFilter" aria-label="Filter rules">
                                                                                <option value="all">All Rules</option>
                                                                                <option value="bans">Bans</option>
                                                                                <option value="whitelists">Whitelists</option>
                                                                                <option value="imports">Imports</option>
                                                                            </select>
                                                                            <input type="text"
                                                                                class="skynet-rules-search"
                                                                                id="skynetRuleSearch"
                                                                                placeholder="Search rules"
                                                                                autocomplete="off"
                                                                                spellcheck="false" />
                                                                        </div>
                                                                        <div class="skynet-rule-header">
                                                                            <span>Type</span>
                                                                            <span>Entry / Group</span>
																											<span>Details</span>
                                                                            <span>Count</span>
                                                                            <span>Action</span>
                                                                        </div>
                                                                        <div id="skynetRuleList">
                                                                            <div class="skynet-feed-empty">Loading firewall rules...</div>
                                                                        </div>
                                                                        <div class="skynet-rules-actions">
                                                                            <span class="skynet-country-status" id="skynetRuleStatus" aria-live="polite"></span>
                                                                            <input type="button"
                                                                                id="skynetApplyRule"
                                                                                value="Apply Rule"
                                                                                class="button_gen skynet-update-button"
                                                                                disabled="disabled" />
                                                                        </div>
                                                                        <div class="skynet-action-panel">
                                                                            <div class="skynet-feed-intro skynet-action-intro">
                                                                                <span class="skynet-feed-title">Recent Activity</span>
                                                                                <span class="skynet-feed-help">Latest firewall, source and settings changes.</span>
                                                                            </div>
                                                                            <div class="skynet-action-header">
                                                                                <span>Time</span>
                                                                                <span>Result</span>
                                                                                <span>Action</span>
                                                                                <span>Details</span>
                                                                            </div>
                                                                            <div class="skynet-action-list" id="skynetRuleActivity">
                                                                                <div class="skynet-feed-empty">Loading recent actions...</div>
                                                                            </div>
                                                                        </div>
                                                                    </div>
                                                                </td>
                                                            </tr>
                                                            <tr class="skynet-settings-group" data-settings-section="iot">
                                                                <th colspan="2">IoT Isolation</th>
                                                            </tr>
                                                            <tr>
                                                                <th>
                                                                    <span class="skynet-setting-name">IoT WAN Blocking</span>
                                                                    <span class="skynet-setting-help">Blocks WAN access for saved devices. Disabling it preserves the device list.</span>
                                                                </th>
                                                                <td>
                                                                    <select class="input_option" id="skynetIotBlocking">
                                                                        <option value="enabled">Enabled</option>
                                                                        <option value="disabled">Disabled (Default)</option>
                                                                    </select>
                                                                </td>
                                                            </tr>
                                                            <tr>
                                                                <th>
                                                                    <span class="skynet-setting-name">IoT Block Logging</span>
                                                                    <span class="skynet-setting-help">Records blocked IoT traffic for statistics while enforcement is enabled.</span>
                                                                </th>
                                                                <td>
                                                                    <select class="input_option" id="skynetIotLogging">
                                                                        <option value="enabled">Enabled (Default)</option>
                                                                        <option value="disabled">Disabled</option>
                                                                    </select>
                                                                </td>
                                                            </tr>
                                                            <tr class="skynet-country-row">
                                                                <th>
                                                                    <span class="skynet-setting-name">IoT Devices</span>
                                                                    <span class="skynet-setting-help">Select a detected client or enter an IPv4 address/CIDR range manually.</span>
                                                                </th>
                                                                <td>
                                                                    <div class="skynet-country-editor">
                                                                        <select class="input_option skynet-country-picker"
                                                                            id="skynetIotPicker"
                                                                            aria-label="Add an IoT device"
                                                                            disabled="disabled">
                                                                            <option value="">Add a detected client...</option>
                                                                        </select>
                                                                        <div class="skynet-iot-add">
                                                                            <input type="text"
                                                                                id="skynetIotManual"
                                                                                maxlength="18"
                                                                                placeholder="IPv4 address or CIDR range"
                                                                                autocomplete="off"
                                                                                spellcheck="false" />
                                                                            <input type="button"
                                                                                id="skynetAddIotManual"
                                                                                value="Add"
                                                                                class="button_gen skynet-update-button skynet-settings-reload" />
                                                                        </div>
                                                                        <div class="skynet-country-list" id="skynetIotList">
                                                                            <span class="skynet-country-empty">Loading IoT devices...</span>
                                                                        </div>
                                                                    </div>
                                                                </td>
                                                            </tr>
                                                            <tr>
                                                                <th>
                                                                    <span class="skynet-setting-name">WAN Port Access</span>
                                                                    <span class="skynet-setting-help">The default permits UDP/123 so isolated devices can synchronize their clocks using NTP. Choose Custom Ports or No Ports to override it.</span>
                                                                </th>
                                                                <td>
                                                                    <div class="skynet-country-editor">
                                                                        <select class="input_option skynet-country-picker"
                                                                            id="skynetIotPortMode"
                                                                            aria-label="Select IoT WAN port access">
                                                                            <option value="default">NTP Time Sync Only (Default)</option>
                                                                            <option value="custom">Custom Ports</option>
                                                                            <option value="none">No Ports</option>
                                                                        </select>
                                                                        <div class="skynet-iot-add">
                                                                            <input type="number"
                                                                                id="skynetIotPortInput"
                                                                                min="1"
                                                                                max="65535"
                                                                                step="1"
                                                                                placeholder="Port"
                                                                                autocomplete="off" />
                                                                            <input type="button"
                                                                                id="skynetAddIotPort"
                                                                                value="Add"
                                                                                class="button_gen skynet-update-button skynet-settings-reload" />
                                                                        </div>
                                                                        <div class="skynet-country-list" id="skynetIotPortList">
                                                                            <span class="skynet-country-empty">UDP/123 is allowed for NTP time synchronization.</span>
                                                                        </div>
                                                                    </div>
                                                                </td>
                                                            </tr>
                                                            <tr>
                                                                <th>
                                                                    <span class="skynet-setting-name">Allowed Protocol</span>
                                                                    <span class="skynet-setting-help">Applies only when Custom Ports is selected.</span>
                                                                </th>
                                                                <td>
                                                                    <select class="input_option" id="skynetIotProtocol">
                                                                        <option value="udp">UDP (Default)</option>
                                                                        <option value="tcp">TCP</option>
                                                                        <option value="all">TCP &amp; UDP</option>
                                                                    </select>
                                                                </td>
                                                            </tr>
                                                            <tr class="skynet-settings-group" data-settings-section="countries">
                                                                <th colspan="2">Country Blocking</th>
                                                            </tr>
                                                            <tr class="skynet-country-row">
                                                                <th>
                                                                    <span class="skynet-setting-name">Blocked Countries</span>
                                                                    <span class="skynet-setting-help">Blocks known IPv4 ranges assigned to the selected countries.</span>
                                                                </th>
                                                                <td>
                                                                    <div class="skynet-country-editor">
                                                                        <select class="input_option skynet-country-picker"
                                                                            id="skynetCountryPicker"
                                                                            aria-label="Add a country"
                                                                            disabled="disabled">
                                                                            <option value="">Add a country...</option>
                                                                        </select>
                                                                    </div>
                                                                </td>
                                                            </tr>
                                                            <tr class="skynet-country-health-container">
                                                                <td colspan="2">
                                                                    <div class="skynet-country-health">
                                                                        <div class="skynet-country-health-header" id="skynetCountryHealthHeader">
                                                                            <span>Country</span>
                                                                            <span>Ranges</span>
                                                                            <span>Last Success</span>
                                                                            <span>State</span>
                                                                            <span>Action</span>
                                                                        </div>
                                                                        <div id="skynetCountryHealthList">
                                                                            <div class="skynet-feed-empty">Loading country source details...</div>
                                                                        </div>
                                                                    </div>
                                                                </td>
                                                            </tr>
                                                            <tr class="skynet-settings-group" data-settings-section="statistics">
                                                                <th colspan="2">Logging &amp; Statistics</th>
                                                            </tr>
                                                            <tr>
                                                                <th>
                                                                    <span class="skynet-setting-name">Invalid Packet Logging</span>
                                                                    <span class="skynet-setting-help">Logs invalid connection-state packets for statistics.</span>
                                                                </th>
                                                                <td>
                                                                    <select class="input_option" id="skynetLogInvalid">
                                                                        <option value="enabled">Enabled</option>
                                                                        <option value="disabled">Disabled (Default)</option>
                                                                    </select>
                                                                </td>
                                                            </tr>
                                                            <tr>
                                                                <th>
                                                                    <span class="skynet-setting-name">Log Size</span>
                                                                    <span class="skynet-setting-help">Sets the log limit before statistics are saved and old entries are cleared.</span>
                                                                </th>
                                                                <td>
                                                                    <div class="skynet-number-control">
                                                                        <input type="number"
                                                                            id="skynetLogSize"
                                                                            min="10"
                                                                            step="1"
                                                                            placeholder="10" />
                                                                        <span class="skynet-input-note">MB · Default: 10MB</span>
                                                                    </div>
                                                                </td>
                                                            </tr>
                                                            <tr>
                                                                <th>
                                                                    <span class="skynet-setting-name">Extended Statistics</span>
                                                                    <span class="skynet-setting-help">Adds associated domain names to blocked IP statistics when available.</span>
                                                                </th>
                                                                <td>
                                                                    <select class="input_option" id="skynetExtendedStats">
                                                                        <option value="enabled">Enabled (Default)</option>
                                                                        <option value="disabled">Disabled</option>
                                                                    </select>
                                                                </td>
                                                            </tr>
                                                            <tr>
                                                                <th>
                                                                    <span class="skynet-setting-name">Country Lookup</span>
                                                                    <span class="skynet-setting-help">Adds country information and grouping to IP statistics.</span>
                                                                </th>
                                                                <td>
                                                                    <select class="input_option" id="skynetCountryLookup">
                                                                        <option value="enabled">Enabled (Default)</option>
                                                                        <option value="disabled">Disabled</option>
                                                                    </select>
                                                                </td>
                                                            </tr>
                                                        </table>
                                                        <div class="skynet-settings-actions">
                                                            <div class="skynet-settings-result"
                                                                id="skynetSettingsResult"
                                                                data-action-sections="updates protection statistics"
                                                                aria-live="polite"></div>
                                                            <div class="skynet-country-status"
                                                                id="skynetIotStatus"
                                                                data-action-sections="iot"
                                                                aria-live="polite"></div>
                                                            <div class="skynet-country-status"
                                                                id="skynetCountryStatus"
                                                                data-action-sections="countries"
                                                                aria-live="polite"></div>
                                                            <input type="button"
                                                                id="skynetRestoreDefaults"
                                                                value="Restore Defaults"
                                                                class="button_gen skynet-update-button skynet-settings-reload"
                                                                data-action-sections="updates protection statistics" />
                                                            <input type="button"
                                                                id="skynetReloadSettings"
                                                                value="Reload Data"
                                                                class="button_gen skynet-update-button skynet-settings-reload"
                                                                data-action-sections="updates protection iot statistics" />
                                                            <input type="button"
                                                                id="skynetApplySettings"
                                                                value="Apply Settings"
                                                                class="button_gen skynet-update-button"
                                                                data-action-sections="updates protection statistics"
                                                                disabled="disabled" />
                                                            <input type="button"
                                                                id="skynetClearIot"
                                                                value="Clear Devices"
                                                                class="button_gen skynet-update-button skynet-settings-reload"
                                                                data-action-sections="iot"
                                                                disabled="disabled" />
                                                            <input type="button"
                                                                id="skynetApplyIot"
                                                                value="Apply IoT"
                                                                class="button_gen skynet-update-button"
                                                                data-action-sections="iot"
                                                                disabled="disabled" />
                                                            <input type="button"
                                                                id="skynetClearCountries"
                                                                value="Clear All"
                                                                class="button_gen skynet-update-button skynet-settings-reload"
                                                                data-action-sections="countries"
                                                                disabled="disabled" />
                                                            <input type="button"
                                                                id="skynetRefreshCountries"
                                                                value="Refresh Sources"
                                                                class="button_gen skynet-update-button skynet-settings-reload"
                                                                data-action-sections="countries"
                                                                disabled="disabled" />
                                                            <input type="button"
                                                                id="skynetApplyCountries"
                                                                value="Apply Countries"
                                                                class="button_gen skynet-update-button"
                                                                data-action-sections="countries"
                                                                disabled="disabled" />
                                                        </div>
                                                    </div>
                                                </div>

                                                <div id="skynetOverviewView" role="tabpanel">
                                                <!-- Skynet dashboard. -->
                                                <div id="skynet_dashboard">
                                                    <div class="skynet-hero">
                                                        <span class="skynet-status"><span class="skynet-status-dot"></span>PROTECTED</span>
                                                        <div class="skynet-hero-core">
                                                            <div class="skynet-hero-title">SKYNET</div>
                                                            <div class="skynet-hero-sub">Router Firewall And Security Enhancements</div>
                                                        </div>
                                                        <a class="skynet-project-link"
                                                            href="https://github.com/Adamm00/IPSet_ASUS"
                                                            target="_blank"
                                                            rel="noopener noreferrer"
                                                            title="Official Skynet repository">ADAMM00 / GITHUB</a>
                                                    </div>

                                                    <div class="skynet-detail" id="skynetDetail" aria-hidden="true">
                                                        <div class="skynet-detail-head">
                                                            <span id="skynetDetailTitle">Skynet Details</span>
                                                            <input type="button"
                                                                id="skynetDetailClose"
                                                                value="Close"
                                                                class="button_gen skynet-detail-close" />
                                                        </div>
                                                        <div class="skynet-detail-body" id="skynetDetailBody"></div>
                                                    </div>

                                                    <table class="skynet-kpis">
                                                        <tr>
                                                            <td class="skynet-kpi">
                                                                <span class="skynet-kpi-label">IPs Banned</span>
                                                                <span class="skynet-kpi-value" id="blcount1">—</span>
                                                            </td>
                                                            <td class="skynet-kpi">
                                                                <span class="skynet-kpi-label">Ranges Banned</span>
                                                                <span class="skynet-kpi-value" id="blcount2">—</span>
                                                            </td>
                                                            <td class="skynet-kpi">
                                                                <span class="skynet-kpi-label">Inbound Blocks</span>
                                                                <span class="skynet-kpi-value" id="hits1">—</span>
                                                            </td>
                                                            <td class="skynet-kpi">
                                                                <span class="skynet-kpi-label">Outbound Blocks</span>
                                                                <span class="skynet-kpi-value" id="hits2">—</span>
                                                            </td>
                                                        </tr>
                                                    </table>

                                                    <table width="100%" border="0" cellpadding="0" cellspacing="0">
                                                        <tr>
                                                            <td class="skynet-actionbar" align="left" style="padding:0;">
                                                                <div class="skynet-update-bar" id="skynetUpdateBar">
                                                                    <div class="skynet-update-info">
                                                                        <div class="skynet-meta" aria-label="Statistics coverage">
                                                                            <span class="skynet-meta-item skynet-meta-period">
                                                                                <span class="skynet-meta-label">Monitoring</span>
                                                                                <span class="skynet-meta-value" id="statsdate">N/A</span>
                                                                            </span>
                                                                            <span class="skynet-meta-item skynet-meta-log">
                                                                                <span class="skynet-meta-label">Log Size</span>
                                                                                <span class="skynet-meta-value" id="statssize">N/A</span>
                                                                            </span>
                                                                        </div>
                                                                        <div class="skynet-update-result" id="skynetUpdateResult" aria-live="polite"></div>
                                                                    </div>
                                                                    <div class="skynet-update-control">
                                                                        <input type="button"
                                                                            id="skynetUpdateStats"
                                                                            value="Refresh Stats"
                                                                            class="button_gen skynet-update-button"
                                                                            aria-label="Update Skynet statistics" />
                                                                    </div>
                                                                </div>
                                                            </td>
                                                        </tr>
                                                    </table>
                                                </div>

                                                <!-- Statistics content insertion point. -->
                                                <div id="skynetDynamicContent"></div>
                                                </div>


                                                <!-- Statistics content. -->

                                                <div style="line-height:10px;">&nbsp;</div>

                                            </td>
                                        </tr>
                                    </tbody>
                                </table>
                            </td>
                        </tr>
                    </table>
                </td>
                <td width="10" align="center" valign="top">&nbsp;</td>
            </tr>
        </table>

        <div id="footer">
        </div>
    </form>
</body>

</html>
