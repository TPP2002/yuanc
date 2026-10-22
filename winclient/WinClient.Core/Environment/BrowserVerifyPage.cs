namespace WinClient.Core.EnvironmentSupport;

public sealed record VerifyContext(string RoutingMode, bool EnvironmentEnabled);

/// <summary>只生成自包含页面；信息由打开页面的浏览器读取。</summary>
public static class BrowserVerifyPage
{
    public const string FileName = "verify.html";
    public const string ExpectedZonePrefix = "Australia/";
    public const string ExpectedLanguage = "en-AU";
    public const string ExpectedCountry = "AU";
    public const string TraceUrl = "https://1.1.1.1/cdn-cgi/trace";
    public const string TunAddressPrefix = "172.19.0.";
    public const string TunAddressPrefixV6 = "fdfe:dcba:9876:";

    public static string Html(VerifyContext context) => $$$"""
        <!doctype html><html lang="zh-CN">
        <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src https://1.1.1.1">
        <title>澳洲出口 · 浏览器复核</title>
        <style>
        :root { --text:#202631; --muted:#596273; --line:#d5dbe3; --bg:#fff; --ok:#186339; --bad:#ac2525; --warn:#805800; --info:#245a91; }
        body { font-family:system-ui,sans-serif; font-size:16px; line-height:1.6; max-width:720px; margin:32px auto; padding:0 16px; color:var(--text); background:var(--bg); }
        h1 { font-size:28px; } table { width:100%; border-collapse:collapse; } th,td { text-align:left; padding:12px 6px; border-bottom:1px solid var(--line); vertical-align:top; }
        td:last-child { overflow-wrap:anywhere; } th:nth-child(3),td:nth-child(3) { min-width:4em; }
        .ok { color:var(--ok); } .bad { color:var(--bad); } .warn { color:var(--warn); } .info { color:var(--info); } .skip,footer { color:var(--muted); }
        #summary { font-weight:600; } button { font:inherit; margin-top:20px; padding:8px 16px; color:var(--text); background:var(--bg); border:1px solid var(--line); border-radius:6px; cursor:pointer; } button:disabled { cursor:wait; } a { color:var(--info); } footer { margin-top:16px; }
        </style>
        </head>
        <body data-mode="{{{(context.RoutingMode == "apps" ? "apps" : "global")}}}" data-env="{{{(context.EnvironmentEnabled ? "on" : "off")}}}">
        <h1>浏览器复核</h1>
        <p>本页只读取这个浏览器自己报告的信息,不改任何设置;结果只代表当前打开本页的浏览器配置档。要在澳洲专用浏览器里核对,把地址栏里的地址复制到那个浏览器打开即可。</p>
        <p id="summary" role="status" aria-live="polite">正在检查…</p>
        <table><thead><tr><th>编号</th><th>项目</th><th>结果</th><th>明细</th></tr></thead><tbody>
        <tr id="check-1"><td>1</td><th scope="row">时区</th><td>正在检查…</td><td></td></tr>
        <tr id="check-2"><td>2</td><th scope="row">首选语言</th><td>正在检查…</td><td></td></tr>
        <tr id="check-3"><td>3</td><th scope="row">定位请求被拒</th><td>正在检查…</td><td></td></tr>
        <tr id="check-4"><td>4</td><th scope="row">WebRTC 本地地址</th><td>正在检查…</td><td></td></tr>
        <tr id="check-5"><td>5</td><th scope="row">浏览器实际出口</th><td>正在检查…</td><td></td></tr>
        </tbody></table>
        <button id="again" type="button">重新检查</button>
        <footer id="checked-at"></footer>
        <script>
        'use strict';
        const expectedZone = '{{{ExpectedZonePrefix}}}';
        const expectedLanguage = '{{{ExpectedLanguage}}}';
        const expectedCountry = '{{{ExpectedCountry}}}';
        const traceUrl = '{{{TraceUrl}}}';
        const tunPrefix = '{{{TunAddressPrefix}}}';
        const tunPrefix6 = '{{{TunAddressPrefixV6}}}';
        const results = [];
        const again = document.getElementById('again');
        const summary = document.getElementById('summary');
        function show(index, result, detail) {
          results[index - 1] = result;
          const cells = document.getElementById('check-' + index).cells;
          cells[2].textContent = result;
          cells[2].className = ({ '通过':'ok', '未通过':'bad', '跳过':'skip', '无法核验':'warn', '信息':'info' })[result];
          cells[3].textContent = detail;
        }
        function manualTrace() {
          const link = document.createElement('a');
          link.href = traceUrl; link.target = '_blank'; link.rel = 'noopener';
          link.textContent = '手动打开查看 loc= 一行';
          document.getElementById('check-5').cells[3].appendChild(link);
        }
        async function localAddresses() {
          if (typeof RTCPeerConnection === 'undefined') throw new Error('接口不可用');
          const peer = new RTCPeerConnection();
          const addresses = [];
          let timer;
          try {
            await new Promise((resolve, reject) => {
              timer = setTimeout(resolve, 3000);
              peer.onicecandidate = event => {
                if (!event.candidate) { resolve(); return; }
                const address = event.candidate.candidate.split(/\s+/)[4];
                if (address) addresses.push(address);
              };
              peer.onicegatheringstatechange = () => { if (peer.iceGatheringState === 'complete') resolve(); };
              peer.createDataChannel('check');
              peer.createOffer().then(offer => peer.setLocalDescription(offer)).catch(reject);
            });
          } finally {
            clearTimeout(timer);
            peer.onicecandidate = null; peer.onicegatheringstatechange = null;
            peer.close();
          }
          return addresses;
        }
        function classify(addresses) {
          let hidden = 0, tunnel = 0, other = 0;
          const lan = [], ipv6 = [];
          for (const address of addresses) {
            if (address.endsWith('.local')) { hidden++; continue; }
            if (address.startsWith(tunPrefix) || address.toLowerCase().startsWith(tunPrefix6)) { tunnel++; continue; }
            const parts = address.split('.');
            const ipv4 = parts.length === 4 && parts.every(part => /^\d{1,3}$/.test(part) && Number(part) <= 255);
            const octets = parts.map(Number);
            if (ipv4) lan.push(address);
            else if (address.includes(':')) ipv6.push(address);
            else other++;
          }
          const exposed = lan.concat(ipv6);
          show(4, exposed.length ? '未通过' : '通过',
            '已隐藏:' + hidden + ',隧道网卡地址:' + tunnel + ',IPv4 明文地址:' + lan.length + ',IPv6 明文地址:' + ipv6.length + ',其他候选:' + other +
            (exposed.length ? ';明文地址:' + exposed.join(', ') : ';未发现隧道网卡以外的明文地址'));
        }
        async function check() {
          if (again.disabled) return;
          again.disabled = true;
          results.length = 0; summary.textContent = '正在检查…'; summary.className = '';
          document.getElementById('checked-at').textContent = '';
          for (let i = 1; i <= 5; i++) {
            const cells = document.getElementById('check-' + i).cells;
            cells[2].textContent = '正在检查…'; cells[2].className = ''; cells[3].textContent = '';
          }
          const enabled = document.body.dataset.env === 'on';
          try {
            if (!enabled) show(1, '跳过', '环境一致性未启用,不核对时区');
            else {
              const zone = Intl.DateTimeFormat().resolvedOptions().timeZone;
              const minutes = -new Date().getTimezoneOffset();
              const offset = 'UTC' + (minutes >= 0 ? '+' : '-') + Math.floor(Math.abs(minutes) / 60) +
                (minutes % 60 ? ':' + String(Math.abs(minutes) % 60).padStart(2, '0') : '');
              show(1, zone.startsWith(expectedZone) ? '通过' : '未通过', zone + ',本地偏移 ' + offset);
            }
          } catch { show(1, '无法核验', '浏览器无法提供时区'); }
          try {
            if (!enabled) show(2, '跳过', '环境一致性未启用,不核对首选语言');
            else {
              const languages = navigator.languages && navigator.languages.length ? Array.from(navigator.languages) : [navigator.language];
              show(2, languages[0].toLowerCase().startsWith(expectedLanguage.toLowerCase()) ? '通过' : '未通过', languages.join(', '));
            }
          } catch { show(2, '无法核验', '浏览器无法提供首选语言'); }
          try {
            if (!enabled) show(3, '跳过', '环境一致性未启用,不核对定位权限');
            else {
              const permission = await navigator.permissions.query({name:'geolocation'});
              if (permission.state === 'denied') show(3, '通过', 'denied:浏览器拒绝定位请求');
              else if (permission.state === 'prompt' || permission.state === 'granted') show(3, '未通过', '浏览器仍会询问或允许定位,策略未生效');
              else show(3, '无法核验', '浏览器返回了未知的定位权限状态');
            }
          } catch { show(3, '无法核验', '浏览器不支持读取定位权限或读取失败'); }
          try { classify(await localAddresses()); }
          catch { show(4, '无法核验', '浏览器不支持读取 WebRTC 本地地址或读取失败'); }
          try {
            const response = await fetch(traceUrl, {cache:'no-store', credentials:'omit', mode:'cors'});
            if (response.status !== 200) throw new Error('出口请求失败');
            const lines = (await response.text()).split(/\r?\n/);
            const locLine = lines.find(line => line.startsWith('loc='));
            if (!locLine || !locLine.slice(4).trim()) throw new Error('缺少国家码');
            const loc = locLine.slice(4).trim();
            const ipLine = lines.find(line => line.startsWith('ip='));
            const ip = ipLine ? ipLine.slice(3).trim() : '未提供';
            if (document.body.dataset.mode === 'apps') show(5, '信息', 'loc=' + loc + '、ip=' + ip + ';仅指定程序模式只有名单里的程序经出口,本结果只代表打开本页的浏览器');
            else show(5, loc === expectedCountry ? '通过' : '未通过', loc === expectedCountry ? 'loc=' + loc + '、ip=' + ip : '出口不在澳洲:loc=' + loc + '、ip=' + ip);
          } catch {
            show(5, '无法核验', '出口请求失败或被浏览器跨站限制拦下;'); manualTrace();
          }
          const passed = results.filter(result => result === '通过').length;
          const failed = results.filter(result => result === '未通过').length;
          summary.textContent = passed + ' 项通过,' + failed + ' 项未通过,' + (5 - passed - failed) + ' 项未能检查';
          summary.className = failed ? 'bad' : passed === 5 ? 'ok' : 'warn';
          document.getElementById('checked-at').textContent = '检查时间:' + new Date().toLocaleString();
          again.disabled = false;
        }
        again.addEventListener('click', check);
        check();
        </script>
        </body></html>
        """;
}
