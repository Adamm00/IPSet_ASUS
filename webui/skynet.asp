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
            --skynet-title: #ffffff;
            --skynet-body: #d7e0e3;
            --skynet-muted-2: #aebcc1;
            --skynet-border-faint: rgba(155, 177, 185, 0.18);
            --skynet-border-medium: rgba(155, 177, 185, 0.34);
            --skynet-surface: #34464c;
            --skynet-surface-2: #2d3d43;
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
        
        .StatsTable th:last-child,
        .StatsTable td:last-child {
            border-right: none !important;
        }

        #FormTitle > tbody > tr > td {
            width: 760px !important;
            max-width: 760px !important;
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
            font-size:11px;
            letter-spacing:0.45px;
            line-height:15px;
        }

        .skynet-status {
            position:absolute;
            top:11px;
            right:12px;
            margin:0;
            padding:5px 10px;
            border-radius:12px;
            background:#30483b;
            color:#a9e5bf;
            border:1px solid #4c8061;
            font-weight:bold;
            font-size:11px;
            z-index:2;
        }
        .skynet-status-dot {
            display:inline-block; width:7px; height:7px; border-radius:50%;
            background:#65c18c; margin-right:5px;
        }

        .skynet-project-link {
            position:absolute;
            top:11px;
            left:12px;
            padding:5px 10px;
            border:1px solid #547d93;
            border-radius:12px;
            background:#2d414b;
            color:#9fd5f1 !important;
            font-size:10px;
            font-weight:bold;
            text-decoration:none;
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
            background:#354247 !important; border:1px solid #607780 !important;
            border-radius:5px; text-align:center; padding:9px 5px !important;
            width:25%;
        }
        .skynet-kpi-label {
            display:block; color:var(--skynet-muted-2) !important; font-size:11px; font-weight:bold;
        }
        .skynet-kpi-value {
            display:block; color:var(--skynet-title) !important; font-size:22px; line-height:25px;
            font-weight:bold; margin-top:3px;
        }
        .skynet-meta {
            color:var(--skynet-muted-2) !important; text-align:center; font-size:11px; margin:2px 0 8px 0;
        }
        .skynet-update-result {
            min-height:15px;
            margin-top:3px;
            color:#b8c4c8;
            font-size:10px;
        }
        .skynet-update-result.error { color:#f2afb5; }
        .skynet-actionbar {
            background:#3a464a !important; border:1px solid #607780 !important;
            border-radius:5px; padding:7px !important;
        }

        /* Navigation and settings. */
        .skynet-tabs {
            display: flex;
            margin: 0 0 10px 0;
            border-bottom: 1px solid var(--skynet-border);
        }

        .skynet-tab {
            min-width: 92px;
            padding: 7px 14px;
            border: 0;
            border-bottom: 2px solid transparent;
            background: transparent;
            color: var(--skynet-muted);
            font-weight: bold;
            cursor: pointer;
        }

        .skynet-tab:hover,
        .skynet-tab.active {
            color: var(--skynet-text);
            background: rgba(255,255,255,0.04);
        }

        .skynet-tab.active {
            border-bottom-color: var(--skynet-link);
        }

        .skynet-tab:focus-visible {
            outline: 2px solid var(--skynet-link);
            outline-offset: -2px;
        }

        .skynet-view-hidden {
            display: none;
        }


        .skynet-update-bar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 10px;
            min-height: 52px;
            margin: 8px 0 10px 0;
            padding: 8px 10px;
            background: var(--skynet-surface);
            border: 1px solid var(--skynet-border-medium);
            border-radius: 5px;
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.03);
            box-sizing: border-box;
            width: 100%;
            max-width: 760px;
        }


        .skynet-update-info > div:last-child {
            margin-top: 2px;
            color: var(--skynet-muted-2) !important;
        }

        .skynet-update-info {
            min-width: 0;
            color: var(--skynet-muted-2) !important;
            font-size: 11px;
            line-height: 15px;
        }

        .skynet-update-title {
            color: var(--skynet-title) !important;
            font-size: 12px;
            font-weight: bold;
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
            border: 1px solid var(--skynet-border);
            border-radius: 5px;
            background: var(--skynet-panel);
        }

        .skynet-settings-table {
            margin: 0 !important;
            border: 0 !important;
        }

        .skynet-settings-table th {
            width: 42%;
        }

        .skynet-settings-group th {
            width: auto;
            padding: 7px 10px;
            background: var(--skynet-panel-alt);
            color: var(--skynet-heading);
            font-size: 10px;
            letter-spacing: 0.6px;
            text-transform: uppercase;
        }

        .skynet-setting-name,
        .skynet-setting-help {
            display: block;
        }

        .skynet-setting-help {
            margin-top: 3px;
            color: var(--skynet-muted);
            font-size: 11px;
            font-weight: normal;
            line-height: 1.4;
        }

        .skynet-settings-table select {
            width: 210px;
            max-width: 100%;
        }

        .skynet-malware-controls {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .skynet-malware-status {
            display: block;
            margin-top: 5px;
            color: var(--skynet-muted);
            font-size: 10px;
        }

        .skynet-malware-update {
            min-width: 96px;
            height: 30px;
        }

        .skynet-settings-table input[type="number"] {
            width: 82px;
        }

        .skynet-settings-table input[type="url"] {
            width: 100%;
            max-width: 360px;
        }

        .skynet-settings-table input[type="number"],
        .skynet-settings-table input[type="url"] {
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
        .skynet-settings-table input[type="url"]::placeholder {
            color: var(--skynet-muted);
            opacity: 0.72;
        }

        .skynet-settings-table input[type="number"]:hover,
        .skynet-settings-table input[type="url"]:hover {
            border-color: var(--skynet-heading);
        }

        .skynet-settings-table input[type="number"]:focus,
        .skynet-settings-table input[type="url"]:focus {
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
            color: var(--skynet-muted);
            font-size: 10px;
        }

        .skynet-country-editor {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .skynet-country-row th {
            padding-top: 13px !important;
            vertical-align: top;
        }

        .skynet-country-picker {
            width: 100% !important;
            max-width: 360px !important;
        }

        .skynet-country-list {
            display: flex;
            flex-wrap: wrap;
            gap: 5px;
            min-height: 26px;
        }

        .skynet-country-tag {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            min-height: 25px;
            padding: 0 5px 0 8px;
            border: 1px solid var(--skynet-border);
            border-radius: 13px;
            background: var(--skynet-panel-alt);
            color: var(--skynet-text);
            font-size: 10px;
        }

        .skynet-country-code {
            color: var(--skynet-muted);
            font-size: 9px;
            text-transform: uppercase;
        }

        .skynet-country-remove {
            width: 18px;
            height: 18px;
            padding: 0;
            border: 0;
            border-radius: 50%;
            background: transparent;
            color: var(--skynet-muted);
            font-size: 15px;
            line-height: 18px;
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
            font-size: 10px;
        }

        .skynet-country-status.error {
            color: #f2afb5;
        }

        .skynet-country-actions {
            display: flex;
            align-items: center;
            justify-content: flex-end;
            gap: 8px;
        }

        .skynet-country-actions .skynet-update-button {
            min-width: 100px;
        }

        .skynet-settings-actions {
            display: flex;
            align-items: center;
            justify-content: flex-end;
            gap: 10px;
            padding: 8px 10px;
            border-top: 1px solid var(--skynet-border-soft);
        }

        .skynet-settings-result {
            flex: 1;
            color: var(--skynet-muted);
            font-size: 10px;
        }

        .skynet-settings-result.error {
            color: #f2afb5;
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
            padding: 6px 8px 6px 12px;
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
            font-size: 10px;
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
            font-size: 10px;
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

        .skynet-detail-copy {
            flex: 0 0 auto;
            min-width: 48px;
            height: 24px;
            padding: 0 7px !important;
            font-size: 10px !important;
        }

        .skynet-detail-copy.copied {
            border-color: #6dbb8d !important;
            background: linear-gradient(#6fae87, #4e8063) !important;
        }

        .skynet-domain-list {
            white-space: pre-line;
        }

        .skynet-detail-actions {
            display: flex;
            justify-content: flex-end;
            gap: 6px;
            margin-top: 10px;
        }
        .skynet-detail-lookup {
            min-width: 108px;
            height: 26px;
            padding: 0 9px !important;
            border-color: #668a9e !important;
            background: #405b67 !important;
            color: #e4f3f8 !important;
            font-size: 10px !important;
            font-weight: bold;
            letter-spacing: 0.1px;
        }
        .skynet-detail-lookup:hover {
            background: #4b6a77 !important;
            border-color: #7eacbf !important;
        }

        .skynet-context-link {
            cursor: pointer;
            color: #f0cf52 !important;
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
            line-height: 16px !important;
        }

        .skynet-section-head {
            background: linear-gradient(#6f7d82, #536167) !important;
            color: #fff !important;
            border: 1px solid #7f9197 !important;
            border-radius: 4px 4px 0 0;
            height: 34px;
            box-sizing: border-box;
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.10);
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
        }

        .skynet-empty-badge {
            display: inline-block;
            margin-left: 8px;
            padding: 1px 6px;
            border: 1px solid var(--skynet-border);
            border-radius: 8px;
            color: var(--skynet-muted);
            font-size: 9px;
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
            padding: 7px 9px !important;
        }

        .skynet-control-label {
            color: var(--skynet-body) !important;
            font-size: 11px;
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
            font-size: 11px !important;
            padding: 7px 6px !important;
            text-align: left !important;
            text-transform: uppercase;
            vertical-align: middle !important;
        }

        .StatsTable.skynet-modern-table td {
            border: 0 !important;
            border-bottom: 1px solid #4b5b61 !important;
            padding: 7px 6px !important;
            color: var(--skynet-text) !important;
            font-size: 11px !important;
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

        .StatsTable.skynet-modern-table .skynet-table-domains {
            text-align: left !important;
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

        .skynet-ip-value {
            font-weight: bold;
            white-space: nowrap;
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
            font-size: 22px;
            line-height: 28px;
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
            font-size:22px !important;
            line-height:28px !important;
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

        @media (max-width: 500px) {
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
                flex-direction: column;
            }

            .skynet-update-button {
                width: 100%;
            }

            .skynet-settings-actions {
                align-items: stretch;
                flex-direction: column;
            }

            .skynet-settings-table select,
            .skynet-settings-actions .skynet-update-button {
                width: 100%;
            }

            .skynet-malware-controls {
                align-items: stretch;
                flex-direction: column;
            }

            .skynet-malware-update {
                width: 100%;
            }

            .skynet-country-actions {
                align-items: stretch;
                flex-direction: column;
            }

            .skynet-country-actions .skynet-update-button {
                width: 100%;
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
            /* Runtime state. */
            charts: Object.create(null),
            chartData: Object.create(null),
            theme: Object.create(null),
            refreshInProgress: false,
            chartResizeBound: false,
            countryNames: Object.create(null),
            countryDisplayNames: null,
            countrySelection: [],
            countryOriginal: "",

            /* Static definitions. */
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
                countryPicker: "skynetCountryPicker",
                countryList: "skynetCountryList",
                countryButton: "skynetApplyCountries",
                countryClear: "skynetClearCountries",
                countryResult: "skynetCountryStatus",
                settingsResult: "skynetSettingsResult",
                overviewTab: "skynetOverviewTab",
                settingsTab: "skynetSettingsTab",
                overviewView: "skynetOverviewView",
                settingsView: "skynetSettingsView"
            },
            actionDefinitions: {
                stats: {
                    button: "updateButton",
                    result: "updateResult",
                    label: "Update Stats",
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
                    label: "Reload Settings",
                    success: "Settings reloaded.",
                    timeout: "Settings reload did not complete.",
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
                    requireSuccess: true
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
                const value = isDomains
                    ? SkynetUI.escapeHtml(field.value).replace(/\s+/g, "\n")
                    : SkynetUI.escapeHtml(field.value);

                const copyValue = SkynetUI.escapeHtml(field.value);
                const copyButton = copyLabels[field.label]
                    ? '<input type="button" class="button_gen skynet-detail-copy" ' +
                        'data-skynet-copy="' + copyValue + '" value="Copy" />'
                    : "";

                rows.push(
                    '<tr>' +
                        '<td>' + SkynetUI.escapeHtml(field.label) + '</td>' +
                        '<td>' +
                            '<div class="skynet-detail-value-wrap">' +
                                '<span class="skynet-detail-value' +
                                    (isDomains ? ' skynet-domain-list' : '') +
                                    '">' + value + '</span>' +
                                copyButton +
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

                if (deviceParts) {
                    fields.push({ label: "IP Address", value: deviceParts[1] });
                    fields.push({ label: "Device Name", value: deviceParts[2] });
                } else {
                    fields.push({ label: "IP Address / Device", value: label });
                }

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
                    const domains = domainsCell ? domainsCell.textContent.trim() : "";
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
                chartContainer.style.height = singleItem ? "250px" : "360px";
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
                                        hidden: false,
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
                return (!item.setting ||
                    (window.SkynetSettings &&
                        window.SkynetSettings[item.setting] === "enabled")) &&
                    Array.isArray(item.values);
            }).map(function(item) {
                const gradient = context.createLinearGradient(0, 0, 0, 270);
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
                    fill: true
                };
            });

            const hasActivity = datasets.some(function(dataset) {
                return dataset.data.some(function(value) {
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
            const columnCount = showCountry ? 5 : 4;
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
            html += '<td><span class="skynet-section-toggle" aria-hidden="true">▾</span></td>';
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
                html += '<col style="width:' + (showCountry ? '245px' : '285px') + ';">';
                html += '<col style="width:82px;">';
                if (showCountry) {
                    html += '<col style="width:70px;">';
                }
                html += '<col style="width:auto;">';

                html += '<thead><tr>';
                html += '<th>IP Address</th>';
                html += '<th>Ban Reason</th>';
                html += '<th class="skynet-table-details">Details</th>';
                if (showCountry) {
                    html += '<th class="skynet-table-country">Country</th>';
                }
                html += '<th class="skynet-table-domains">Associated Domains</th>';
                html += '</tr></thead>';

                const reasons = window["Label" + name + "_BanReason"] || [];
                const alienVault = window["Label" + name + "_AlienVault"] || [];
                const countries = showCountry
                    ? window["Label" + name + "_Country"] || []
                    : [];
                const domains = window["Label" + name + "_AssDomains"] || [];

                ips.forEach(function(ip, index) {
                    const escapedIp = SkynetUI.escapeHtml(ip);
                    const escapedReason = SkynetUI.escapeHtml(reasons[index] || "");
                    const escapedCountry = SkynetUI.escapeHtml(countries[index] || "");
                    const domainValue = domains[index] === "*"
                        ? ""
                        : domains[index] || "";
                    const escapedDomains = SkynetUI.escapeHtml(domainValue)
                        .replace(/ /g, "\n");
                    const url = SkynetUI.escapeHtml(alienVault[index] || "#");

                    html += '<tr>';
                    html += '<td><span class="skynet-ip-value">' + escapedIp + '</span></td>';
                    html += '<td class="skynet-table-reason">' + escapedReason + '</td>';
                    html += '<td class="skynet-table-details"><a class="skynet-external-link" target="_blank" rel="noopener" href="' +
                        url + '">View</a></td>';
                    if (showCountry) {
                        html += '<td class="skynet-table-country">' + escapedCountry + '</td>';
                    }
                    html += '<td class="skynet-table-domains" style="white-space:pre;">' + escapedDomains + '</td>';
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

        };

        /* Settings and country management. */
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
            const clear = this.getElement(this.selectors.countryClear);

            if (picker) {
                picker.disabled = busy || !supported;
            }
            if (apply) {
                apply.disabled = busy || !supported || !this.isCountryDirty();
            }
            if (clear) {
                clear.disabled = busy || !supported || !this.countrySelection.length;
            }
            document.querySelectorAll(".skynet-country-remove").forEach(function(button) {
                button.disabled = busy || !supported;
            });
        };

        SkynetUI.renderCountries = function() {
            const list = this.getElement(this.selectors.countryList);

            if (!list) {
                return;
            }

            while (list.firstChild) {
                list.removeChild(list.firstChild);
            }

            if (!this.countrySelection.length) {
                const empty = document.createElement("span");
                empty.className = "skynet-country-empty";
                empty.textContent = "No countries are currently blocked.";
                list.appendChild(empty);
            } else {
                this.countrySelection.forEach(function(code) {
                    const tag = document.createElement("span");
                    const name = document.createElement("span");
                    const countryCode = document.createElement("span");
                    const remove = document.createElement("button");

                    tag.className = "skynet-country-tag";
                    name.textContent = SkynetUI.getCountryName(code);
                    countryCode.className = "skynet-country-code";
                    countryCode.textContent = code;
                    remove.type = "button";
                    remove.className = "skynet-country-remove";
                    remove.dataset.country = code;
                    remove.title = "Remove " + SkynetUI.getCountryName(code);
                    remove.setAttribute("aria-label", remove.title);
                    remove.textContent = "×";
                    remove.disabled = SkynetUI.refreshInProgress;
                    tag.appendChild(name);
                    tag.appendChild(countryCode);
                    tag.appendChild(remove);
                    list.appendChild(tag);
                });
            }

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
                this.populateCountries();
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

            this.populateMalwareStatus();
            this.populateBlacklistCounts(settings);
            this.populateCountries();

            if (apply && !this.refreshInProgress) {
                apply.disabled = false;
            }
            if (malware && !this.refreshInProgress) {
                malware.disabled = !this.canUpdateMalware();
            }

            const result = this.getElement(this.selectors.settingsResult);

            if (result && result.textContent === "Reload settings to load current values.") {
                result.textContent = "";
            }
        };

        /* Background actions. */
        SkynetUI.setUpdateResult = function(message, isError, resultSelector) {
            const result = this.getElement(resultSelector || this.selectors.updateResult);

            if (!result) {
                return;
            }

            result.textContent = message || "";
            result.classList.toggle("error", Boolean(isError));
        };

        SkynetUI.setActionState = function(active, buttonSelector, label) {
            [
                this.selectors.updateButton,
                this.selectors.settingsButton,
                this.selectors.settingsReloadButton,
                this.selectors.settingsDefaultsButton,
                this.selectors.malwareButton,
                this.selectors.countryButton,
                this.selectors.countryClear
            ].forEach(function(id) {
                const button = SkynetUI.getElement(id);

                if (button) {
                    button.disabled = active ||
                        (id === SkynetUI.selectors.settingsButton &&
                            (!window.SkynetSettings || !window.SkynetSettingsGenerated)) ||
                        (id === SkynetUI.selectors.malwareButton &&
                            !SkynetUI.canUpdateMalware()) ||
                        ((id === SkynetUI.selectors.countryButton ||
                            id === SkynetUI.selectors.countryClear) &&
                            !SkynetUI.canManageCountries()) ||
                        (id === SkynetUI.selectors.countryButton &&
                            !SkynetUI.isCountryDirty()) ||
                        (id === SkynetUI.selectors.countryClear &&
                            !SkynetUI.countrySelection.length);
                    button.classList.toggle("skynet-update-busy", active && id === buttonSelector);
                }
            });

            const picker = this.getElement(this.selectors.countryPicker);
            if (picker) {
                picker.disabled = active || !this.canManageCountries();
            }
            document.querySelectorAll(".skynet-country-remove").forEach(function(remove) {
                remove.disabled = active || !SkynetUI.canManageCountries();
            });

            const button = this.getElement(buttonSelector);

            if (button && label) {
                button.value = label;
            }
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
            const self = this;
            const action = this.actionDefinitions[requestType] ||
                this.actionDefinitions.stats;
            const button = this.selectors[action.button];
            const result = this.selectors[action.result];
            const loadSettings = action.source === "settings";
            const request = loadSettings
                ? this.loadSettingsScript()
                : this.loadStatsScript();

            request.then(function() {
                const currentStamp = loadSettings
                    ? window.SkynetSettingsGenerated
                    : window.SkynetStatsGenerated;

                if (String(currentStamp || "") !== String(previousStamp || "")) {
                    const failed = action.requireSuccess &&
                        window.SkynetSettingsResult !== "success";

                    if (loadSettings) {
                        self.refreshRenderedStats();
                        if (requestType !== "countries" || !failed) {
                            self.populateSettings();
                        }
                    } else {
                        self.refreshRenderedStats();
                    }
                    self.refreshInProgress = false;
                    if (failed) {
                        self.setUpdateResult(
                            requestType === "countries"
                                ? self.getCountryUpdateError()
                                : action.failure,
                            true,
                            result
                        );
                        self.setActionState(false, button, "Try Again");
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
                self.setActionState(false, button, "Try Again");
            }).catch(function() {
                if (attempts > 0) {
                    window.setTimeout(function() {
                        self.waitForUpdate(previousStamp, attempts - 1, requestType);
                    }, 1000);
                    return;
                }

                self.refreshInProgress = false;
                self.setUpdateResult(action.loadError, true, result);
                self.setActionState(false, button, "Try Again");
            });
        };

        SkynetUI.updateStats = function() {
            if (this.refreshInProgress) {
                return;
            }

            this.refreshInProgress = true;
            this.setUpdateResult("Generating statistics...", false);
            this.setActionState(true, this.selectors.updateButton, "Updating...");
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

        SkynetUI.updateCountries = function() {
            if (this.refreshInProgress || !this.canManageCountries() ||
                !this.isCountryDirty()) {
                return;
            }

            custom_settings.skynet_countrylist = this.countrySelection.join(" ");
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

        SkynetUI.submitBackgroundAction = function(action) {
            const settings = this.getElement("amng_custom");

            document.form.action_script.value = action;
            document.form.submit();

            if (settings) {
                settings.value = "";
            }
        };

        SkynetUI.restoreDefaultSettings = function() {
            const defaults = {
                skynetAutoUpdate: "enabled",
                skynetMalwareUpdates: "daily",
                skynetMalwareUrl: "",
                skynetFilterTraffic: "all",
                skynetUnbanPrivate: "enabled",
                skynetAiProtect: "enabled",
                skynetSecureMode: "enabled",
                skynetLogInvalid: "disabled",
                skynetLogSize: "10",
                skynetExtendedStats: "enabled",
                skynetCountryLookup: "enabled",
                skynetCdnWhitelist: "enabled",
                skynetIotBlocking: "disabled",
                skynetIotLogging: "enabled"
            };

            Object.keys(defaults).forEach(function(id) {
                const field = SkynetUI.getElement(id);

                if (field) {
                    field.value = defaults[id];
                }
            });

            this.setUpdateResult(
                "Default values loaded. Apply Settings to save.",
                false,
                this.selectors.settingsResult
            );
        };

        SkynetUI.updateSettings = function() {
            if (this.refreshInProgress) {
                return;
            }

            const logsize = this.getElement("skynetLogSize").value;
            const customlisturl = this.getElement("skynetMalwareUrl").value.trim();

            if (!/^\d+$/.test(logsize) || Number(logsize) < 10) {
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
            custom_settings.skynet_iotblocked = this.getElement("skynetIotBlocking").value;
            custom_settings.skynet_iotlogging = this.getElement("skynetIotLogging").value;

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

            this.refreshInProgress = true;
            this.setUpdateResult("Reloading settings...", false, this.selectors.settingsResult);
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

        SkynetUI.showView = function(view) {
            const settings = view === "settings";
            const overviewTab = this.getElement(this.selectors.overviewTab);
            const settingsTab = this.getElement(this.selectors.settingsTab);
            const overviewView = this.getElement(this.selectors.overviewView);
            const settingsView = this.getElement(this.selectors.settingsView);

            if (overviewTab) {
                overviewTab.classList.toggle("active", !settings);
                overviewTab.setAttribute("aria-selected", String(!settings));
            }

            if (settingsTab) {
                settingsTab.classList.toggle("active", settings);
                settingsTab.setAttribute("aria-selected", String(settings));
            }

            if (overviewView) {
                overviewView.classList.toggle("skynet-view-hidden", settings);
            }

            if (settingsView) {
                settingsView.classList.toggle("skynet-view-hidden", !settings);
            }

            if (settings) {
                this.populateSettings();
            } else {
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

            const countryPicker = this.getElement(this.selectors.countryPicker);

            if (countryPicker) {
                countryPicker.addEventListener("change", function() {
                    SkynetUI.addCountry(this.value);
                });
            }

            const countryList = this.getElement(this.selectors.countryList);

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

            const apply = this.getElement(this.selectors.settingsButton);

            if (apply) {
                apply.addEventListener("click", function() {
                    SkynetUI.updateSettings();
                });
            }

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
            const settingsTab = this.getElement(this.selectors.settingsTab);

            if (overviewTab) {
                overviewTab.addEventListener("click", function() {
                    SkynetUI.showView("overview");
                });
            }

            if (settingsTab) {
                settingsTab.addEventListener("click", function() {
                    SkynetUI.showView("settings");
                });
            }
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

            this.bindControls();

            const initialiseCharts = function() {
                Object.keys(SkynetUI.chartDefinitions).forEach(function(chartName) {
                    const definition = SkynetUI.chartDefinitions[chartName];

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
                                                        id="skynetSettingsTab"
                                                        value="Settings"
                                                        class="skynet-tab"
                                                        role="tab"
                                                        aria-controls="skynetSettingsView"
                                                        aria-selected="false" />
                                                </div>

                                                <div id="skynetSettingsView" class="skynet-view-hidden" role="tabpanel">
                                                    <div class="skynet-settings">
                                                        <table class="FormTable skynet-settings-table">
                                                            <tr class="skynet-settings-group">
                                                                <th colspan="2">Updates</th>
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
                                                            <tr class="skynet-settings-group">
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
                                                                    <span class="skynet-setting-help">Automatically whitelists private addresses found in blocked traffic.</span>
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
                                                                    <span class="skynet-setting-name">IoT Blocking</span>
                                                                    <span class="skynet-setting-help">Blocks internet access for devices in the IoT list. Disabling keeps the saved list.</span>
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
                                                                    <span class="skynet-setting-help">Records blocked IoT traffic for statistics when IoT blocking is enabled.</span>
                                                                </th>
                                                                <td>
                                                                    <select class="input_option" id="skynetIotLogging">
                                                                        <option value="enabled">Enabled (Default)</option>
                                                                        <option value="disabled">Disabled</option>
                                                                    </select>
                                                                </td>
                                                            </tr>
                                                            <tr>
                                                                <th>
                                                                    <span class="skynet-setting-name">Import AiProtection Bans</span>
                                                                    <span class="skynet-setting-help">Imports threats detected by AiProtection into Skynet.</span>
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
                                                            <tr class="skynet-settings-group">
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
                                                                        <div class="skynet-country-list" id="skynetCountryList">
                                                                            <span class="skynet-country-empty">Loading blocked countries...</span>
                                                                        </div>
                                                                        <div class="skynet-country-status"
                                                                            id="skynetCountryStatus"
                                                                            aria-live="polite"></div>
                                                                        <div class="skynet-country-actions">
                                                                            <input type="button"
                                                                                id="skynetClearCountries"
                                                                                value="Clear All"
                                                                                class="button_gen skynet-update-button skynet-settings-reload"
                                                                                disabled="disabled" />
                                                                            <input type="button"
                                                                                id="skynetApplyCountries"
                                                                                value="Apply Countries"
                                                                                class="button_gen skynet-update-button"
                                                                                disabled="disabled" />
                                                                        </div>
                                                                    </div>
                                                                </td>
                                                            </tr>
                                                            <tr class="skynet-settings-group">
                                                                <th colspan="2">Statistics</th>
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
                                                            <div class="skynet-settings-result" id="skynetSettingsResult" aria-live="polite"></div>
                                                            <input type="button"
                                                                id="skynetRestoreDefaults"
                                                                value="Restore Defaults"
                                                                class="button_gen skynet-update-button skynet-settings-reload" />
                                                            <input type="button"
                                                                id="skynetReloadSettings"
                                                                value="Reload Settings"
                                                                class="button_gen skynet-update-button skynet-settings-reload" />
                                                            <input type="button"
                                                                id="skynetApplySettings"
                                                                value="Apply Settings"
                                                                class="button_gen skynet-update-button"
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

                                                    <div class="skynet-meta">
                                                        <span id="statsdate">Monitoring From - N/A</span>
                                                        &nbsp;&nbsp;•&nbsp;&nbsp;
                                                        <span id="statssize">Log Size - N/A</span>
                                                    </div>

                                                    <table width="100%" border="0" cellpadding="0" cellspacing="0">
                                                        <tr>
                                                            <td class="skynet-actionbar" align="left" style="padding:0;">
                                                                <div class="skynet-update-bar" id="skynetUpdateBar">
                                                        <div class="skynet-update-info">
                                                            <div class="skynet-update-title">Statistics</div>
                                                            <div>Refresh the current Skynet statistics from the router log.</div>
                                                            <div class="skynet-update-result" id="skynetUpdateResult" aria-live="polite"></div>
                                                        </div>
                                                        <input type="button"
                                                            id="skynetUpdateStats"
                                                            value="Update Stats"
                                                            class="button_gen skynet-update-button"
                                                            aria-label="Update Skynet statistics" />
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
