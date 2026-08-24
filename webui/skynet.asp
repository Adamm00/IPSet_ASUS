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
        #skynet_dashboard { margin:0 0 10px 0; }
        .skynet-hero {
            position:relative;
            background:
                linear-gradient(180deg,#3c4b50 0%,#303d41 100%);
            border:1px solid #6b8fa3;
            border-radius:6px;
            padding:15px 16px 14px 16px;
            margin-bottom:10px;
            box-shadow:
                inset 0 1px 0 rgba(255,255,255,0.08),
                0 1px 2px rgba(0,0,0,0.14);
            text-align:center;
        }

        .skynet-hero-title {
            display:inline-block;
            position:relative;
            color:#ffffff !important;
            font-size:17px;
            font-weight:bold;
            letter-spacing:0.15px;
            line-height:24px;
            text-shadow:0 1px 1px rgba(0,0,0,0.22);
            padding-bottom:4px;
        }

        .skynet-hero-title::after {
            content:"";
            display:block;
            width:34px;
            height:2px;
            margin:4px auto 0 auto;
            border-radius:2px;
            background:#79b7d3;
            opacity:0.9;
        }

        .skynet-hero-sub {
            margin-top:2px;
            color:#bfcacd !important;
            font-size:11px;
            line-height:16px;
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
        }
        .skynet-status-dot {
            display:inline-block; width:7px; height:7px; border-radius:50%;
            background:#65c18c; margin-right:5px;
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
            display:block; color:#b8c4c8; font-size:11px; font-weight:bold;
        }
        .skynet-kpi-value {
            display:block; color:#fff; font-size:22px; line-height:25px;
            font-weight:bold; margin-top:3px;
        }
        .skynet-meta {
            color:#b8c4c8; text-align:center; font-size:11px; margin:2px 0 8px 0;
        }
        .skynet-actionbar {
            background:#3a464a !important; border:1px solid #607780 !important;
            border-radius:5px; padding:7px !important;
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


        :root {
            --skynet-bg: #2f3e44;
            --skynet-panel: #354247;
            --skynet-panel-alt: #39484e;
            --skynet-border: #607780;
            --skynet-border-soft: #53666d;
            --skynet-row-border: rgba(115, 137, 145, 0.14);
            --skynet-text: #eef2f3;
            --skynet-muted: #b8c4c8;
            --skynet-heading: #dfe7ea;
            --skynet-link: #8fd1f5;
            --skynet-green: #65c18c;
        }


        .skynet-update-bar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 10px;
            margin: 8px 0 10px 0;
            padding: 8px 10px;
            background: var(--skynet-panel);
            border: 1px solid var(--skynet-border);
            border-radius: 5px;
            box-sizing: border-box;
            width: 100%;
            max-width: 760px;
        }


        .skynet-update-info > div:last-child {
            margin-top: 2px;
            color: var(--skynet-muted-2) !important;
        }

        .skynet-update-bar {
            min-height: 52px;
        }

        .skynet-update-info {
            min-width: 0;
            color: var(--skynet-muted);
            font-size: 11px;
            line-height: 15px;
        }

        .skynet-update-title {
            color: var(--skynet-heading);
            font-size: 12px;
            font-weight: bold;
        }

        .skynet-update-button {
            min-width: 112px;
            height: 32px;
            padding: 0 14px !important;
            border: 1px solid #7ba6bb !important;
            border-radius: 5px !important;
            background: linear-gradient(#6ea6bf, #4f7f95) !important;
            color: #fff !important;
            font-weight: bold !important;
            text-shadow: 0 1px 1px rgba(0,0,0,0.35);
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.12),
                        0 1px 2px rgba(0,0,0,0.20);
            cursor: pointer;
            transition: transform 120ms ease, filter 120ms ease;
        }

        .skynet-update-button:disabled,
        .skynet-update-button.skynet-update-busy {
            opacity: 0.72;
            cursor: wait;
            filter: saturate(0.75);
        }

        .skynet-update-button:hover {
            filter: brightness(1.08);
        }

        .skynet-update-button:active {
            transform: translateY(1px);
        }

        .skynet-update-button:focus-visible {
            outline: 2px solid #8fd1f5;
            outline-offset: 2px;
        }

        @media (max-width: 500px) {
            .skynet-update-bar {
                align-items: stretch;
                flex-direction: column;
            }

            .skynet-update-button {
                width: 100%;
            }
        }

        .skynet-detail {
            display: none;
            width: 100% !important;
            max-width: 760px !important;
            margin: 8px 0 10px 0;
            background: var(--skynet-panel);
            border: 1px solid var(--skynet-border);
            border-radius: 6px;
            box-sizing: border-box;
            overflow: hidden;
            box-shadow: 0 2px 5px rgba(0,0,0,0.16);
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
            background: linear-gradient(#6f7d82, #536167);
            border-bottom: 1px solid #71848a;
            color: #fff;
            padding: 6px 8px 6px 12px;
            font-size: 13px;
            font-weight: bold;
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
            background: #2f3e44;
            border: 1px solid #50656d;
            border-radius: 5px;
            box-sizing: border-box;
        }

        .skynet-detail-identity-text {
            min-width: 0;
        }

        .skynet-detail-identity-label {
            color: var(--skynet-muted);
            font-size: 10px;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 0.35px;
        }

        .skynet-detail-identity-value {
            margin-top: 2px;
            color: #fff;
            font-size: 17px;
            line-height: 21px;
            font-weight: bold;
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
            background: #354247;
        }

        .skynet-detail-grid td {
            padding: 7px 8px;
            border-bottom: 1px solid rgba(115, 137, 145, 0.16);
            vertical-align: middle;
        }

        .skynet-detail-grid tr:last-child td {
            border-bottom: 0;
        }

        .skynet-detail-grid td:first-child {
            width: 150px;
            color: var(--skynet-muted);
            font-weight: bold;
        }

        .skynet-detail-grid td + td {
            border-left: 1px solid rgba(115, 137, 145, 0.24);
            color: var(--skynet-text);
        }


        .skynet-detail-grid td:first-child {
            white-space: nowrap;
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

        .skynet-context-link {
            cursor: pointer;
            color: #f4d03f !important;
            font-weight: bold !important;
            text-decoration: none !important;
        }

        .skynet-context-link:hover {
            text-decoration: underline !important;
        }

        .skynet-context-selected {
            text-decoration: underline !important;
        }


        /* Skynet visual theme. */
        :root {
            --skynet-title: #ffffff;
            --skynet-body: #d7e0e3;
            --skynet-muted-2: #aebcc1;
            --skynet-accent: #8fd1f5;
            --skynet-border-faint: rgba(155, 177, 185, 0.18);
            --skynet-border-medium: rgba(155, 177, 185, 0.34);
            --skynet-surface: #34464c;
            --skynet-surface-2: #2d3d43;
        }

        .skynet-section-head {
            background: linear-gradient(180deg, #66767b 0%, #536267 100%) !important;
            border: 1px solid #75858a !important;
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.10);
        }

        .skynet-section-head td {
            color: var(--skynet-title) !important;
            line-height: 18px !important;
        }

        .skynet-controls {
            background: var(--skynet-surface-2) !important;
            border-color: var(--skynet-border-medium) !important;
        }

        .skynet-control-label {
            color: var(--skynet-body) !important;
            letter-spacing: 0.25px;
        }

        .skynet-chart-shell {
            background: var(--skynet-surface-2);
            border: 1px solid var(--skynet-border-faint);
        }

        .skynet-chart-shell canvas {
            display: block;
        }

        .skynet-modern-table {
            background: var(--skynet-surface) !important;
        }


        .StatsTable.skynet-modern-table thead th,
        .StatsTable.skynet-modern-table tbody td {
            font-family: inherit !important;
            box-sizing: border-box !important;
        }

        .StatsTable.skynet-modern-table th,
        .StatsTable.skynet-modern-table td {
            line-height: 16px !important;
        }

        .StatsTable.skynet-modern-table th {
            color: #dbe4e7 !important;
            background: #2f4046 !important;
            border-bottom: 1px solid var(--skynet-border-medium) !important;
            line-height: 16px !important;
        }

        .StatsTable.skynet-modern-table td {
            color: var(--skynet-body) !important;
            border-bottom: 1px solid var(--skynet-border-faint) !important;
            line-height: 16px !important;
        }

        .StatsTable.skynet-modern-table th + th,
        .StatsTable.skynet-modern-table td + td {
            border-left: 1px solid var(--skynet-border-faint) !important;
        }

        .StatsTable.skynet-modern-table tr:nth-child(even) td {
            background: #3a4a50 !important;
        }

        .StatsTable.skynet-modern-table tr:hover td {
            background: #42545a !important;
        }

        .skynet-kpi-label,
        .skynet-meta,
        .skynet-update-info {
            color: var(--skynet-muted-2) !important;
        }

        .skynet-kpi-value {
            color: var(--skynet-title) !important;
        }

        .skynet-detail {
            background: var(--skynet-surface);
            border-color: var(--skynet-border-medium);
            box-shadow:
                0 2px 6px rgba(0,0,0,0.18),
                inset 0 1px 0 rgba(255,255,255,0.03);
        }

        .skynet-detail-head {
            background: linear-gradient(180deg, #66767b 0%, #536267 100%);
            border-bottom-color: #75858a;
            text-shadow: 0 1px 1px rgba(0,0,0,0.24);
        }

        .skynet-detail-identity {
            background: var(--skynet-surface-2);
            border-color: var(--skynet-border-medium);
        }

        .skynet-detail-identity-label {
            color: var(--skynet-muted-2);
        }

        .skynet-detail-identity-value {
            color: var(--skynet-title);
            letter-spacing: 0.15px;
        }

        .skynet-detail-grid {
            background: var(--skynet-surface);
        }

        .skynet-detail-grid td {
            color: var(--skynet-body);
            border-bottom-color: var(--skynet-border-faint);
        }

        .skynet-detail-grid td:first-child {
            color: var(--skynet-muted-2);
            text-transform: uppercase;
            font-size: 10px;
            letter-spacing: 0.2px;
        }

        .skynet-detail-grid td + td {
            border-left-color: var(--skynet-border-faint);
            color: var(--skynet-body);
        }

        .skynet-detail-value {
            color: var(--skynet-title);
        }

        .skynet-context-link,
        .skynet-external-link {
            color: #f0cf52 !important;
        }

        .skynet-update-bar {
            background: var(--skynet-surface);
            border-color: var(--skynet-border-medium);
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.03);
        }

        .skynet-update-title {
            color: var(--skynet-title) !important;
        }

        .skynet-update-button {
            border-color: #8ab0c2 !important;
            background: linear-gradient(180deg, #6ea6bf 0%, #4f7f95 100%) !important;
        }

        .skynet-nodata {
            color: var(--skynet-muted-2) !important;
            background: var(--skynet-surface-2);
        }

        /* Skynet visual theme. */
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

        .skynet-modern-table th + th,
        .skynet-modern-table td + td {
            border-left: 1px solid #60767d !important;
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
            box-sizing: border-box;
        }

        .skynet-section-head {
            background: linear-gradient(#6f7d82, #536167) !important;
            color: #fff !important;
            border: 1px solid #7f9197 !important;
            border-radius: 4px 4px 0 0;
            height: 34px;
            box-sizing: border-box;
        }

        .skynet-section-head td {
            font-size: 13px !important;
            font-weight: bold !important;
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

        .skynet-controls {
            background: var(--skynet-panel) !important;
            border-left: 1px solid var(--skynet-border) !important;
            border-right: 1px solid var(--skynet-border) !important;
            border-bottom: 1px solid var(--skynet-border) !important;
            padding: 7px 9px !important;
        }

        .skynet-control-label {
            color: #d7dfe2;
            font-size: 11px;
            font-weight: bold;
            margin-right: 5px;
            text-transform: uppercase;
        }
.skynet-chart-shell {
            position: relative;
            width: 100%;
            height: 360px;
            background: var(--skynet-bg);
            border: 1px solid #43565d;
            border-radius: 0 0 7px 7px;
            box-sizing: border-box;
            padding: 8px;
        }


        .skynet-chart-shell canvas {
            display: block;
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


        /* Skynet visual theme. */

        .skynet-section-head {
            background: linear-gradient(#6f7d82, #536167) !important;
            color: #fff !important;
            border: 1px solid #7f9197 !important;
            border-radius: 4px 4px 0 0;
            height: 34px;
            box-sizing: border-box;
        }

        .skynet-section-head td {
            font-size: 13px !important;
            font-weight: bold !important;
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

        .skynet-controls {
            background: var(--skynet-panel) !important;
            border-left: 1px solid var(--skynet-border) !important;
            border-right: 1px solid var(--skynet-border) !important;
            border-bottom: 1px solid var(--skynet-border) !important;
            padding: 7px 9px !important;
        }

        .skynet-control-label {
            color: #d7dfe2;
            font-size: 11px;
            font-weight: bold;
            margin-right: 5px;
            text-transform: uppercase;
        }

        .skynet-chart-shell {
            position: relative;
            width: 100%;
            height: 360px;
            background: var(--skynet-bg);
            border: 1px solid #43565d;
            border-radius: 0 0 7px 7px;
            box-sizing: border-box;
            padding: 8px;
        }

        .skynet-chart-shell canvas {
            width: 100% !important;
            height: 100% !important;
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
            table-layout: fixed !important;
            border: 0 !important;
            background: var(--skynet-panel) !important;
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
        }

        .StatsTable.skynet-modern-table td {
            border: 0 !important;
            border-bottom: 1px solid #4b5b61 !important;
            padding: 7px 6px !important;
            color: var(--skynet-text) !important;
            font-size: 11px !important;
            vertical-align: top;
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
            color: #cfd7da;
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

        .skynet-nodata {
            min-height: 180px;
            box-sizing: border-box;
            padding: 24px;
            display: flex !important;
            align-items: center;
            justify-content: center;
            color: #cfd7da;
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

        @media (max-width: 900px) {
            .skynet-control-group {
                display: block;
                margin: 0 0 6px 0;
            }

            .skynet-chart-shell {
                height: 320px;
            }
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

    </style>
    <script src="/js/chart.min.js"></script>
    <script src="/ext/skynet/stats.js"></script>
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
        /*
         * Skynet WebUI client layer.
         * Integrates Skynet statistics with the native Asuswrt-Merlin page.
         */


        const SkynetUI = {
            charts: Object.create(null),
            chartData: Object.create(null),
            theme: Object.create(null),
            chartColors: [
                "#5DADE2", "#58D68D", "#F5B041", "#EC7063", "#AF7AC5",
                "#48C9B0", "#F4D03F", "#5499C7", "#45B39D", "#DC7633"
            ],
            chartDefinitions: {
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
                statsAnchor: "skynet_table_keystats",
                updateButton: "skynetUpdateStats"
            }
        };

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

            /*
             * Convert compact country codes to localized display names when
             * supported by the browser, with the original code as fallback.
             */
            if (typeof Intl !== "undefined" &&
                typeof Intl.DisplayNames === "function") {
                try {
                    const names = new Intl.DisplayNames(["en-AU"], {
                        type: "region"
                    });
                    const name = names.of(code);

                    if (name && name !== code) {
                        return name;
                    }
                } catch (error) {
                    /* Retain the original value when the clipboard API is unavailable. */
                }
            }

            return code;
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
                    type: "pie",
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
                        '<input type="button" class="button_gen" ' +
                        'data-skynet-detail-url="' +
                        SkynetUI.escapeHtml(action.url) +
                        '" value="' +
                        SkynetUI.escapeHtml(action.label) +
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
                chartName === "TCConnHits") return "Outbound";
            return "";
        };

        SkynetUI.getStatisticName = function(chartName) {
            if (chartName === "TIConnHits" || chartName === "TOConnHits") {
                return "Blocked Connections";
            }
            if (chartName === "THConnHits") return "HTTP(s) Blocks";
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
            const domains = window["Label" + chartName + "_AssDomains"];
            return Array.isArray(domains) && domains[index]
                ? String(domains[index]).trim()
                : "";
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

            const countries = window["Label" + chartName + "_Country"];
            const reasons = window["Label" + chartName + "_BanReason"];
            const alienVault = window["Label" + chartName + "_AlienVault"];
            const domains = this.getAssociatedDomains(chartName, index);
            const country = Array.isArray(countries) ? (countries[index] || "") : "";
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

                    const cells = row.querySelectorAll("td");
                    const reason = cells[1] ? cells[1].textContent.trim() : "";
                    const country = cells[3] ? cells[3].textContent.trim() : "";
                    const domains = cells[4] ? cells[4].textContent.trim() : "";
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

        SkynetUI.getChartTarget = function(chartName, multiLabel, index) {
            if (chartName === "InPortHits" || chartName === "SPortHits") {
                const labels = window["Label" + chartName];

                return labels && labels[index]
                    ? "https://www.speedguide.net/port.php?port=" +
                        encodeURIComponent(labels[index])
                    : "";
            }

            if (chartName === "TCConnHits") {
                return "";
            }

            const group = this.getElement(chartName + "_Group");
            const groupValue = group ? Number(group.value) : 0;

            if (multiLabel === "true" && groupValue === 1) {
                return "";
            }

            const labels = window["Label" + chartName + "_IPs"];

            return labels && labels[index]
                ? "https://otx.alienvault.com/indicator/ip/" +
                    encodeURIComponent(labels[index])
                : "";
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

            const countries = window["Label" + chartName + "_Country"];
            const reasons = window["Label" + chartName + "_BanReason"];

            const meta = {
                title: "IP: " + label,
                label: "Hits: " + hits,
                detail: this.getDirection(chartName)
            };

            if (Array.isArray(countries) && countries[index]) {
                meta.country = "Country: " +
                    this.getCountryName(countries[index]);
            }

            if (Array.isArray(reasons) && reasons[index]) {
                meta.reason = "Ban Reason: " + reasons[index];
            }

            return meta;
        };

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
            const isPie = configuration.type === "pie";
            const singleItem = !isPie && source.data.length === 1;
            const textColor = this.getChartTextColor();
            const gridColor = this.getChartGridColor();

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

            const dataset = {
                data: source.data,
                borderWidth: 1,
                borderColor: isPie ? "#1F2528" : colors,
                backgroundColor: colors
            };

            const options = {
                responsive: true,
                maintainAspectRatio: false,
                animation: {
                    duration: 250,
                    easing: "easeOutQuart"
                },
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
                            color: gridColor
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
                            color: gridColor
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
                canvas.getContext("2d"),
                {
                    type: configuration.type,
                    data: {
                        labels: chartLabels,
                        datasets: [dataset]
                    },
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

            this.restoreSelect(chartName + "_Type", 0, 2);

            if (multiLabel === "true") {
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

        SkynetUI.setSectionState = function(section, expanded) {
            const table = section.closest(".skynet-section > table") ||
                section.parentElement;

            const bodyRows = table
                ? table.querySelectorAll(".skynet-section-body-row")
                : [];

            section.classList.toggle("expanded", expanded);
            section.classList.toggle("collapsed", !expanded);
            section.setAttribute("aria-expanded", expanded ? "true" : "false");

            bodyRows.forEach(function(row) {
                row.style.display = expanded ? "" : "none";
            });

            if (!expanded) {
                const chartName = section.id.replace("skynet_chart_", "");

                if (section.id.indexOf("skynet_chart_") === 0) {
                    this.destroyChart(chartName);
                }
            } else if (section.id.indexOf("skynet_chart_") === 0) {
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

            this.setCookie(
                section.id,
                expanded ? "expanded" : "collapsed"
            );
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

            if (multiLabel === "true") {
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
            html += '<option value="2">Pie</option>';
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

        SkynetUI.buildTableHtml = function(title, name) {
            const ips = window["Label" + name + "_IPs"];
            const noData = !Array.isArray(ips) ||
                !ips.length ||
                (ips.length === 1 && ips[0] === "");

            let html = "";
            html += '<div class="skynet-section">';
            html += '<table width="100%" border="0" cellpadding="0" cellspacing="0">';

            html += '<thead class="collapsible expanded skynet-section-head" id="skynet_table_' + name + '" aria-expanded="true" role="button" tabindex="0">';
            html += '<tr>';
            html += '<td>' + this.escapeHtml(title) + '</td>';
            html += '<td><span class="skynet-section-toggle" aria-hidden="true">▾</span></td>';
            html += '</tr>';
            html += '</thead>';

            html += '<tbody>';
            html += '<tr class="skynet-section-body-row">';
            html += '<td colspan="2" style="padding:0;">';
            html += '<div class="skynet-table-shell">';

            html += '<table class="FormTable StatsTable skynet-modern-table">';

            if (noData) {
                html += '<tr><td colspan="5" class="skynet-nodata skynet-table-nodata">No data to display</td></tr>';
            } else {
                html += '<col style="width:120px;">';
                html += '<col style="width:245px;">';
                html += '<col style="width:82px;">';
                html += '<col style="width:70px;">';
                html += '<col style="width:auto;">';

                html += '<thead><tr>';
                html += '<th>IP Address</th>';
                html += '<th>Ban Reason</th>';
                html += '<th>Details</th>';
                html += '<th>Country</th>';
                html += '<th>Associated Domains</th>';
                html += '</tr></thead>';

                const reasons = window["Label" + name + "_BanReason"] || [];
                const alienVault = window["Label" + name + "_AlienVault"] || [];
                const countries = window["Label" + name + "_Country"] || [];
                const domains = window["Label" + name + "_AssDomains"] || [];

                ips.forEach(function(ip, index) {
                    const escapedIp = SkynetUI.escapeHtml(ip);
                    const escapedReason = SkynetUI.escapeHtml(reasons[index] || "");
                    const escapedCountry = SkynetUI.escapeHtml(countries[index] || "");
                    const escapedDomains = SkynetUI.escapeHtml(domains[index] || "")
                        .replace(/ /g, "\n");
                    const url = SkynetUI.escapeHtml(alienVault[index] || "#");

                    html += '<tr>';
                    html += '<td><span class="skynet-ip-value">' + escapedIp + '</span></td>';
                    html += '<td>' + escapedReason + '</td>';
                    html += '<td><a class="skynet-external-link" target="_blank" rel="noopener" href="' +
                        url + '">View</a></td>';
                    html += '<td>' + escapedCountry + '</td>';
                    html += '<td style="white-space:pre;">' + escapedDomains + '</td>';
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

        SkynetUI.updateStats = function() {
            document.form.action_script.value = "start_SkynetStats";

            const wait = Number(document.form.action_wait.value) || 45;

            parent.showLoading(wait, "waiting");
            document.form.submit();
        };

        SkynetUI.bindControls = function() {
            document.querySelectorAll("[id$='_Type']").forEach(function(element) {
                const chartName = element.id.substring(
                    0,
                    element.id.indexOf("_")
                );
                const multiLabel =
                    ["TOConnHits", "TIConnHits", "THConnHits"].indexOf(chartName) !== -1
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

            const update = this.getElement(this.selectors.updateButton);

            if (update) {
                update.addEventListener("click", function() {
                    if (this.disabled) {
                        return;
                    }

                    this.disabled = true;
                    this.value = "Updating...";
                    this.classList.add("skynet-update-busy");

                    SkynetUI.updateStats();
                });
            }
        };

        SkynetUI.renderChartsAndTables = function() {
            const anchor = this.getElement(this.selectors.statsAnchor);

            if (!anchor) {
                return false;
            }

            const content = [];

            Object.keys(this.chartDefinitions).forEach(function(chartName) {
                const definition = SkynetUI.chartDefinitions[chartName];

                content.push(
                    SkynetUI.buildChartHtml(
                        definition.title,
                        chartName,
                        definition.multiLabel ? "true" : "false"
                    )
                );
            });

            Object.keys(this.tableDefinitions).forEach(function(tableName) {
                content.push(
                    SkynetUI.buildTableHtml(
                        SkynetUI.tableDefinitions[tableName],
                        tableName
                    )
                );
            });

            anchor.insertAdjacentHTML("afterend", content.join(""));

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

            SetStatsDate();
            SetStatsSize();
            SetBLCount1();
            SetBLCount2();
            SetHits1();
            SetHits2();
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


                                                <!-- Skynet dashboard. -->
                                                <div id="skynet_dashboard">
                                                    <div class="skynet-hero">
                                                        <span class="skynet-status"><span class="skynet-status-dot"></span>PROTECTED</span>
                                                        <div class="skynet-hero-title">Skynet Firewall</div>
                                                        <div class="skynet-hero-sub">Network security overview and threat statistics</div>
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
                                                <table width="100%" border="0" cellpadding="0" cellspacing="0"
                                                       id="skynet_table_keystats" style="display:none;">
                                                    <tr><td></td></tr>
                                                </table>


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