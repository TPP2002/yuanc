(function () {
  'use strict';

  /* 全局状态:csrf 只放内存变量,不落任何存储 */
  var csrf = '';
  var nodeNameValue = '';
  var inviteMode = true;
  var currentTab = 'status';
  var statusTimer = null;
  var invitesCache = [];
  var accountsCache = [];
  var devicesCache = [];
  var openExtend = null;
  var openConfirm = null;
  var SVG_NS = 'http:' + '//www.w3.org/2000/svg';

  /* 骨架里的固定元素,一律按 id 取 */
  var loginView = document.getElementById('login');
  var loginForm = document.getElementById('login-form');
  var loginPassword = document.getElementById('login-password');
  var loginSubmit = document.getElementById('login-submit');
  var loginMsg = document.getElementById('login-msg');
  var appView = document.getElementById('app');
  var nodeNameEl = document.getElementById('node-name');
  var nodeVersionEl = document.getElementById('node-version');
  var logoutBtn = document.getElementById('logout');
  var tabsEl = document.getElementById('tabs');
  var tabStatus = document.getElementById('tab-status');
  var tabInvites = document.getElementById('tab-invites');
  var tabAccounts = document.getElementById('tab-accounts');
  var pageMsg = document.getElementById('page-msg');
  var viewStatus = document.getElementById('view-status');
  var stateTile = document.getElementById('state-tile');
  var stateName = document.getElementById('state-name');
  var stateReason = document.getElementById('state-reason');
  var stateMeta = document.getElementById('state-meta');
  var publicIp = document.getElementById('public-ip');
  var checkedAt = document.getElementById('checked-at');
  var staleEl = document.getElementById('stale');
  var layersTitle = document.getElementById('layers-title');
  var layersEl = document.getElementById('layers');
  var localTitle = document.getElementById('local-title');
  var localDevices = document.getElementById('local-devices');
  var viewInvites = document.getElementById('view-invites');
  var inviteForm = document.getElementById('invite-form');
  var invDays = document.getElementById('inv-days');
  var invUses = document.getElementById('inv-uses');
  var invNote = document.getElementById('inv-note');
  var invSubmit = document.getElementById('inv-submit');
  var invMsg = document.getElementById('inv-msg');
  var invNew = document.getElementById('inv-new');
  var invNewCode = document.getElementById('inv-new-code');
  var invNewMeta = document.getElementById('inv-new-meta');
  var invNewCopy = document.getElementById('inv-new-copy');
  var invitesEl = document.getElementById('invites');
  var invitesEmpty = document.getElementById('invites-empty');
  var viewAccounts = document.getElementById('view-accounts');
  var accountsEl = document.getElementById('accounts');
  var accountsEmpty = document.getElementById('accounts-empty');

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  /* 按固定表画小方块的记号,不认任何外部内容 */
  function svgPath(d, width) {
    var node = document.createElementNS(SVG_NS, 'path');
    node.setAttribute('d', d);
    if (width) node.setAttribute('stroke-width', width);
    return node;
  }

  function svgCircle() {
    var node = document.createElementNS(SVG_NS, 'circle');
    node.setAttribute('cx', '12');
    node.setAttribute('cy', '12');
    node.setAttribute('r', '4.6');
    node.setAttribute('stroke-dasharray', '2.3 2.3');
    return node;
  }

  function svgGroup(className) {
    var node = document.createElementNS(SVG_NS, 'g');
    node.setAttribute('class', className);
    return node;
  }

  function glyphNodes(name) {
    if (name === 'check') return [svgPath('m7 12.4 3.3 3.3 6.7-7.4')];
    if (name === 'x') return [svgPath('m8.5 8.5 7 7M15.5 8.5l-7 7')];
    if (name === 'ring') return [svgCircle()];
    if (name === 'bang') return [svgPath('M12 7v5.5'), svgPath('M12 16.8h.01', '2.8')];
    if (name === 'ask') {
      var ask = svgGroup('a-pulse');
      ask.appendChild(svgPath('M9.4 9.3a2.7 2.7 0 1 1 3.9 2.3c-1 .5-1.3 1.1-1.3 2.1'));
      ask.appendChild(svgPath('M12 17.4h.01', '2.8'));
      return [ask];
    }
    var spin = svgGroup('a-spin');
    spin.appendChild(svgPath('M7 12.6a5 5 0 1 0 1.6-3.7'));
    spin.appendChild(svgPath('M6.4 6.2v3.4h3.4'));
    return [spin];
  }

  function setTile(node, size, tone, glyph, extras, label) {
    node.className = 'tile ' + size + ' ' + tone + (extras ? ' ' + extras : '');
    node.setAttribute('role', 'img');
    node.setAttribute('aria-label', label);
    clear(node);
    var inner = document.createElement('i');
    var svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    var parts = glyphNodes(glyph);
    for (var i = 0; i < parts.length; i++) svg.appendChild(parts[i]);
    inner.appendChild(svg);
    node.appendChild(inner);
  }

  function makeTile(size, tone, glyph, extras, label) {
    var node = el('span');
    setTile(node, size, tone, glyph, extras, label);
    return node;
  }

  /* 时间一律按浏览器本地时区显示 */
  function parseDate(value) {
    if (!value) return null;
    var date = new Date(value);
    return isNaN(date.getTime()) ? null : date;
  }

  function dateValue(value) {
    var date = parseDate(value);
    return date ? date.getTime() : 0;
  }

  function pad2(number) {
    return number < 10 ? '0' + number : String(number);
  }

  function dateText(value) {
    var date = parseDate(value);
    if (!date) return '—';
    return date.getFullYear() + '-' + pad2(date.getMonth() + 1) + '-' + pad2(date.getDate());
  }

  function shortDate(value) {
    var date = parseDate(value);
    if (!date) return '—';
    return pad2(date.getMonth() + 1) + '-' + pad2(date.getDate());
  }

  function shortTime(value) {
    var date = parseDate(value);
    if (!date) return '—';
    return shortDate(value) + ' ' + pad2(date.getHours()) + ':' + pad2(date.getMinutes());
  }

  function ageText(age) {
    if (age < 0) return '时间不对';
    if (age < 60) return '刚刚';
    if (age < 3600) return Math.floor(age / 60) + ' 分钟前';
    if (age < 86400) return Math.floor(age / 3600) + ' 小时前';
    return Math.floor(age / 86400) + ' 天前';
  }

  function platformText(platform) {
    if (platform === 'windows') return 'Windows';
    if (platform === 'android') return '安卓';
    return platform;
  }

  function makeError(message, code, status) {
    var error = new Error(message);
    error.code = code || '';
    error.status = status || 0;
    return error;
  }

  /* 统一请求:同源凭据,POST 带 JSON 与防伪头 */
  function api(method, path, body) {
    var headers = {Accept: 'application/json'};
    var options = {method: method, credentials: 'same-origin', headers: headers};
    if (method !== 'GET') {
      headers['Content-Type'] = 'application/json';
      if (csrf) headers['X-Console-CSRF'] = csrf;
      options.body = JSON.stringify(body || {});
    }
    return fetch(path, options).then(function (response) {
      return response.text().then(function (raw) {
        var data = null;
        try {
          data = JSON.parse(raw);
        } catch (error) {
          data = null;
        }
        if (data === null) {
          throw makeError('管理网页出错了,请稍后再试', 'bad_response', response.status);
        }
        return {status: response.status, ok: response.ok, data: data};
      }, function () {
        throw makeError('连不上节点,请检查网络后再试', 'network', 0);
      });
    }, function () {
      throw makeError('连不上节点,请检查网络后再试', 'network', 0);
    });
  }

  /* 业务请求:401 且 code 为 login_required 时转登录界面 */
  function request(method, path, body) {
    return api(method, path, body).then(function (response) {
      var data = response.data;
      if (response.status === 401 && data && data.code === 'login_required') {
        handleExpired();
        throw makeError('登录已过期,请重新登录', 'login_required', 401);
      }
      if (!response.ok) {
        var detail = data && typeof data.detail === 'string' ? data.detail : '管理网页出错了,请稍后再试';
        var code = data && typeof data.code === 'string' ? data.code : '';
        throw makeError(detail, code, response.status);
      }
      return data;
    });
  }

  function clearPageMsg() {
    pageMsg.textContent = '';
    pageMsg.classList.remove('bad');
  }

  function showPageError(message) {
    pageMsg.textContent = message;
    pageMsg.classList.add('bad');
  }

  function setBlockError(node, message) {
    node.textContent = message;
    node.classList.add('bad');
  }

  function setBusy(button, busy, text) {
    if (busy) button.setAttribute('aria-busy', 'true');
    else button.removeAttribute('aria-busy');
    button.textContent = text;
  }

  function isBusy(button) {
    return button.getAttribute('aria-busy') === 'true';
  }

  /* 界面切换与登录、退出、页签 */
  function showLogin(message) {
    appView.hidden = true;
    loginView.hidden = false;
    loginMsg.textContent = message || '';
  }

  function enterApp(session) {
    csrf = session.csrf || '';
    nodeNameValue = session.node_name || '';
    inviteMode = session.invite_mode !== false;
    loginView.hidden = true;
    appView.hidden = false;
    nodeNameEl.textContent = nodeNameValue;
    document.title = nodeNameValue + ' · 节点管理';
    tabsEl.hidden = !inviteMode;
    selectTab('status');
  }

  function resetSession() {
    stopStatusRefresh();
    closeExtend();
    closeConfirm();
    csrf = '';
    invitesCache = [];
    accountsCache = [];
    devicesCache = [];
  }

  function handleExpired() {
    resetSession();
    showLogin('登录已过期,请重新登录');
  }

  function bindLogin() {
    loginForm.addEventListener('submit', function (event) {
      event.preventDefault();
      if (isBusy(loginSubmit)) return;
      var password = loginPassword.value.trim();
      if (!password) {
        loginMsg.textContent = '请填管理密码';
        loginPassword.focus();
        return;
      }
      loginMsg.textContent = '';
      setBusy(loginSubmit, true, '正在登录');
      api('POST', '/api/login', {password: password}).then(function (response) {
        var data = response.data || {};
        if (response.ok) {
          loginPassword.value = '';
          enterApp(data);
          return;
        }
        if (data.code === 'wrong_password') {
          loginMsg.textContent = '密码不对。忘了密码可以在节点上运行 exitnode console password 换一个';
        } else {
          loginMsg.textContent = typeof data.detail === 'string' ? data.detail : '管理网页出错了,请稍后再试';
        }
        loginPassword.focus();
        loginPassword.select();
      }, function (error) {
        loginMsg.textContent = error.message;
        loginPassword.focus();
        loginPassword.select();
      }).then(function () {
        setBusy(loginSubmit, false, '登录');
      });
    });
  }

  function bindLogout() {
    logoutBtn.addEventListener('click', function () {
      if (isBusy(logoutBtn)) return;
      setBusy(logoutBtn, true, '正在退出');
      api('POST', '/api/logout').then(function () {}, function () {}).then(function () {
        resetSession();
        setBusy(logoutBtn, false, '退出登录');
        showLogin('');
      });
    });
  }

  var TAB_DEFS = [
    {name: 'status', button: tabStatus, view: viewStatus},
    {name: 'invites', button: tabInvites, view: viewInvites},
    {name: 'accounts', button: tabAccounts, view: viewAccounts}
  ];

  function bindTabs() {
    for (var i = 0; i < TAB_DEFS.length; i++) {
      bindTab(TAB_DEFS[i]);
    }
  }

  function bindTab(definition) {
    definition.button.addEventListener('click', function () {
      selectTab(definition.name);
    });
  }

  function selectTab(name) {
    currentTab = name;
    for (var i = 0; i < TAB_DEFS.length; i++) {
      var definition = TAB_DEFS[i];
      var selected = definition.name === name;
      definition.button.setAttribute('aria-selected', selected ? 'true' : 'false');
      definition.view.hidden = !selected;
    }
    clearPageMsg();
    closeConfirm();
    if (name === 'status') {
      loadStatus();
      startStatusRefresh();
    } else {
      stopStatusRefresh();
      loadDirectory();
    }
  }

  /* 状态页:30 秒刷新与整页渲染 */
  function startStatusRefresh() {
    stopStatusRefresh();
    statusTimer = window.setInterval(function () {
      if (currentTab === 'status' && document.visibilityState === 'visible') loadStatus();
    }, 30000);
  }

  function stopStatusRefresh() {
    if (statusTimer !== null) {
      window.clearInterval(statusTimer);
      statusTimer = null;
    }
  }

  function onVisibilityChange() {
    if (document.visibilityState === 'visible' && currentTab === 'status' && statusTimer !== null) {
      loadStatus();
    }
  }

  function loadStatus() {
    request('GET', '/api/status').then(function (data) {
      renderStatus(data || {});
      clearPageMsg();
    }, function (error) {
      if (error.code === 'login_required') return;
      showPageError(error.message);
    });
  }

  function renderStatus(data) {
    if (!data.available) {
      setTile(stateTile, 's40', 'tone-n', 'ring', '', '还没有检查记录');
      stateName.textContent = '还没有检查记录';
      stateReason.textContent = '装好两分钟后仍没有,请在节点上运行 exitnode check';
      stateMeta.hidden = true;
      staleEl.hidden = true;
      layersTitle.hidden = true;
      layersEl.hidden = true;
      clear(layersEl);
      localTitle.hidden = true;
      localDevices.hidden = true;
      clear(localDevices);
      nodeVersionEl.textContent = '';
      return;
    }
    nodeVersionEl.textContent = data.program_version || '';
    if (data.node_name) {
      nodeNameValue = data.node_name;
      nodeNameEl.textContent = data.node_name;
    }
    stateMeta.hidden = false;
    layersTitle.hidden = false;
    layersEl.hidden = false;
    renderHeroState(data);
    stateReason.textContent = data.reason || '';
    publicIp.textContent = data.public_ipv4 ? data.public_ipv4 : '未取到';
    checkedAt.textContent = ageText(data.age_seconds);
    renderStale(data);
    renderLayers(data.layers || []);
    renderLocalDevices(data.local_devices || []);
  }

  function renderStale(data) {
    if (!data.stale) {
      staleEl.hidden = true;
      return;
    }
    staleEl.hidden = false;
    if (data.age_seconds < 0) {
      staleEl.textContent = '这份记录的时间比现在还晚,节点时钟可能不准';
    } else {
      staleEl.textContent = '这份记录是' + ageText(data.age_seconds) + '的,节点上的定时检查可能停了';
    }
  }

  /* 状态页:总状态、各层检查、本机自用设备 */
  function renderHeroState(data) {
    var state = data.state;
    var label = '需要处理';
    var tone = 'tone-bad';
    var glyph = 'bang';
    var extras = '';
    if (state === 'normal') {
      label = '正常';
      tone = 'tone-ok';
      glyph = 'check';
      extras = 'fill';
    } else if (state === 'reconnecting') {
      label = '正在重连';
      tone = 'tone-info';
      glyph = 'spin';
      extras = 'spec';
    } else if (state === 'reauth') {
      label = '需要重新授权';
      tone = 'tone-warn';
      glyph = 'ask';
      extras = 'spec fast';
    } else if (state !== 'manual') {
      label = String(state);
      tone = 'tone-n';
      glyph = 'ask';
    }
    setTile(stateTile, 's40', tone, glyph, extras, label);
    stateName.textContent = label;
  }

  function renderLayers(layers) {
    clear(layersEl);
    for (var i = 0; i < layers.length; i++) layersEl.appendChild(layerRow(layers[i]));
  }

  function layerRow(layer) {
    var result = layer.result || '';
    var tone = 'tone-n';
    var glyph = 'ask';
    var badge = 'n';
    var extras = '';
    if (result === '通过') {
      tone = 'tone-ok';
      glyph = 'check';
      badge = 'ok';
    } else if (result === '失败') {
      tone = 'tone-bad';
      glyph = 'x';
      badge = 'bad';
    } else if (result === '需重新授权') {
      tone = 'tone-warn';
      glyph = 'ask';
      badge = 'warn';
    } else if (result === '需手动转发') {
      tone = 'tone-warn';
      glyph = 'bang';
      badge = 'warn';
    } else if (result === '未接入') {
      glyph = 'ring';
    } else if (result === '跳过') {
      glyph = 'ring';
      extras = 'dim';
    }
    var row = el('div', 'row');
    row.appendChild(makeTile('s20', tone, glyph, extras, result));
    row.appendChild(el('span', 'label', layer.name || ''));
    row.appendChild(el('span', 'val', layer.reason || ''));
    row.appendChild(el('span', 'badge ' + badge, result));
    return row;
  }

  function renderLocalDevices(devices) {
    clear(localDevices);
    if (devices.length === 0) {
      localTitle.hidden = true;
      localDevices.hidden = true;
      return;
    }
    localTitle.hidden = false;
    localDevices.hidden = false;
    for (var i = 0; i < devices.length; i++) localDevices.appendChild(localDeviceRow(devices[i]));
  }

  function localDeviceRow(device) {
    var row = el('div', 'row dev');
    row.appendChild(el('span', 'label', platformText(device.platform)));
    row.appendChild(el('span', 'val', device.name || ''));
    if (device.revoked_at) {
      row.classList.add('off');
      row.appendChild(el('span', 'badge n', '已吊销'));
    } else {
      row.appendChild(el('span', 'rt', shortDate(device.created_at) + ' 加入'));
    }
    return row;
  }

  /* 邀请码页:表单、快捷天数、生成 */
  function collectChips(root) {
    var chips = [];
    var buttons = root.getElementsByTagName('button');
    for (var i = 0; i < buttons.length; i++) {
      if (buttons[i].getAttribute('data-days')) chips.push(buttons[i]);
    }
    return chips;
  }

  function syncChips(chips, value) {
    var text = String(value).trim();
    for (var i = 0; i < chips.length; i++) {
      var match = chips[i].getAttribute('data-days') === text;
      chips[i].setAttribute('aria-pressed', match ? 'true' : 'false');
    }
  }

  function parseDays(value) {
    var text = String(value).trim();
    if (!/^[0-9]+$/.test(text)) return null;
    var days = Number(text);
    return days >= 1 && days <= 3650 ? days : null;
  }

  function parseUses(value) {
    var text = String(value).trim();
    if (!/^[0-9]+$/.test(text)) return null;
    var uses = Number(text);
    return uses >= 1 && uses <= 100 ? uses : null;
  }

  function bindDayChip(chip, input, chips) {
    chip.addEventListener('click', function () {
      input.value = chip.getAttribute('data-days');
      syncChips(chips, input.value);
    });
  }

  function bindInviteForm() {
    var chips = collectChips(inviteForm);
    for (var i = 0; i < chips.length; i++) bindDayChip(chips[i], invDays, chips);
    invDays.addEventListener('input', function () {
      syncChips(chips, invDays.value);
    });
    inviteForm.addEventListener('submit', function (event) {
      event.preventDefault();
      submitInvite();
    });
  }

  function submitInvite() {
    if (isBusy(invSubmit)) return;
    var days = parseDays(invDays.value);
    if (days === null) {
      invMsg.textContent = '天数要填 1 到 3650 的整数';
      invDays.focus();
      return;
    }
    var uses = parseUses(invUses.value);
    if (uses === null) {
      invMsg.textContent = '人数要填 1 到 100 的整数';
      invUses.focus();
      return;
    }
    var note = invNote.value.trim();
    if (Array.from(note).length > 200) {
      invMsg.textContent = '备注最多 200 个字,不能换行';
      invNote.focus();
      return;
    }
    invMsg.textContent = '';
    setBusy(invSubmit, true, '正在生成');
    request('POST', '/api/invites', {days: days, max_uses: uses, note: note}).then(function (data) {
      var invite = data.invite || {};
      invNew.hidden = false;
      invNewCode.textContent = invite.code || '';
      var meta = invite.days + ' 天 · ' + invite.max_uses + ' 人可用';
      if (invite.note) meta += ' · ' + invite.note;
      invNewMeta.textContent = meta;
      invNewCopy.textContent = '复制';
      invNote.value = '';
      loadDirectory();
    }, function (error) {
      if (error.code !== 'login_required') invMsg.textContent = error.message;
    }).then(function () {
      setBusy(invSubmit, false, '生成');
    });
  }

  /* 邀请码页:列表与复制 */
  function renderInvites() {
    clear(invitesEl);
    for (var i = 0; i < invitesCache.length; i++) invitesEl.appendChild(inviteRow(invitesCache[i]));
    invitesEmpty.hidden = invitesCache.length > 0;
  }

  function inviteRow(invite) {
    var row = el('div', 'row inv');
    var codeEl = el('span', 'code', invite.code || '');
    row.appendChild(codeEl);
    row.appendChild(el('span', 'num', invite.days + ' 天 · 已用 ' + invite.used + '/' + invite.max_uses));
    row.appendChild(el('span', 'val', invite.note || ''));
    row.appendChild(el('span', 'rt', shortDate(invite.created_at) + ' 生成'));
    if (Number(invite.used) < Number(invite.max_uses)) {
      var copyBtn = el('button', 'btn quiet sm', '复制');
      copyBtn.type = 'button';
      copyBtn.addEventListener('click', function () {
        copyCode(codeEl.textContent, copyBtn, codeEl);
      });
      row.appendChild(copyBtn);
    } else {
      row.classList.add('off');
      row.appendChild(el('span', 'badge n', '已用完'));
    }
    return row;
  }

  function copyCode(text, button, codeEl) {
    var done = function () {
      button.textContent = '已复制';
      window.setTimeout(function () {
        button.textContent = '复制';
      }, 2000);
    };
    var failed = function () {
      selectNode(codeEl);
      showPageError('浏览器不让自动复制,邀请码已选中,请手动复制');
    };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done, failed);
      return;
    }
    var area = document.createElement('textarea');
    area.value = text;
    area.readOnly = true;
    area.style.position = 'fixed';
    area.style.top = '-1000px';
    area.style.left = '-1000px';
    document.body.appendChild(area);
    area.select();
    var ok = false;
    try {
      ok = document.execCommand('copy');
    } catch (error) {
      ok = false;
    }
    document.body.removeChild(area);
    if (ok) done();
    else failed();
  }

  function selectNode(node) {
    var selection = window.getSelection();
    if (selection && selection.selectAllChildren) selection.selectAllChildren(node);
  }

  function bindInvites() {
    invNewCopy.addEventListener('click', function () {
      copyCode(invNewCode.textContent, invNewCopy, invNewCode);
    });
  }

  /* 目录:邀请码、账号、设备一起取 */
  function loadDirectory() {
    request('GET', '/api/directory').then(function (data) {
      invitesCache = data.invites || [];
      accountsCache = data.accounts || [];
      devicesCache = data.devices || [];
      renderInvites();
      renderAccounts();
      clearPageMsg();
    }, function (error) {
      if (error.code === 'login_required') return;
      showPageError(error.message);
    });
  }

  var GROUP_ORDER = {'使用中': 0, '已过期': 1, '已停用': 2};

  function groupOf(account, now) {
    if (account.status === 'disabled') return '已停用';
    return dateValue(account.expires_at) > now ? '使用中' : '已过期';
  }

  function renderAccounts() {
    closeExtend();
    closeConfirm();
    clear(accountsEl);
    var now = Date.now();
    var entries = [];
    for (var i = 0; i < accountsCache.length; i++) {
      var account = accountsCache[i];
      entries.push({account: account, group: groupOf(account, now)});
    }
    entries.sort(function (left, right) {
      var byGroup = GROUP_ORDER[left.group] - GROUP_ORDER[right.group];
      if (byGroup !== 0) return byGroup;
      var byExpiry = dateValue(left.account.expires_at) - dateValue(right.account.expires_at);
      if (byExpiry !== 0) return byExpiry;
      return dateValue(right.account.created_at) - dateValue(left.account.created_at);
    });
    for (var j = 0; j < entries.length; j++) {
      accountsEl.appendChild(accountCard(entries[j].account, entries[j].group, now));
    }
    accountsEmpty.hidden = entries.length > 0;
  }

  function findInvite(code) {
    for (var i = 0; i < invitesCache.length; i++) {
      if (invitesCache[i].code === code) return invitesCache[i];
    }
    return null;
  }

  function accountDevices(account) {
    var devices = [];
    for (var i = 0; i < devicesCache.length; i++) {
      if (devicesCache[i].account_id === account.id) devices.push(devicesCache[i]);
    }
    devices.sort(function (left, right) {
      var revokedDiff = (left.revoked_at ? 1 : 0) - (right.revoked_at ? 1 : 0);
      if (revokedDiff !== 0) return revokedDiff;
      var leftSeen = left.last_seen ? dateValue(left.last_seen) : -1;
      var rightSeen = right.last_seen ? dateValue(right.last_seen) : -1;
      return rightSeen - leftSeen;
    });
    return devices;
  }

  /* 账号页:一块账号 */
  function accountCard(account, group, now) {
    var card = el('article', 'card acct');
    var msg = el('p', 'msg');
    msg.setAttribute('role', 'alert');
    var invite = findInvite(account.invite_code);
    var hasNote = !!(invite && typeof invite.note === 'string' && invite.note !== '');
    var meta = buildMeta(account, hasNote);
    var head = el('div', 'acct-head');
    var badgeClass = group === '使用中' ? 'ok' : (group === '已过期' ? 'warn' : 'n');
    head.appendChild(el('span', 'badge ' + badgeClass, group));
    var title = el('span', 'acct-title');
    if (hasNote) {
      title.textContent = invite.note;
    } else {
      title.textContent = account.invite_code || '';
      title.classList.add('mono');
    }
    head.appendChild(title);
    head.appendChild(buildExpiry(account, group, now));
    head.appendChild(buildActions(account, group, card, meta, msg));
    card.appendChild(head);
    card.appendChild(meta);
    var devices = accountDevices(account);
    if (devices.length > 0) card.appendChild(deviceRows(devices, msg));
    card.appendChild(msg);
    return card;
  }

  function buildMeta(account, hasNote) {
    var node = el('p', 'acct-meta');
    var first = true;
    function append(part) {
      if (!first) node.appendChild(document.createTextNode(' · '));
      first = false;
      node.appendChild(part);
    }
    if (hasNote) {
      var invitePart = document.createElement('span');
      invitePart.appendChild(document.createTextNode('邀请码 '));
      invitePart.appendChild(el('span', 'mono', account.invite_code || ''));
      append(invitePart);
    }
    append(document.createTextNode('设备 ' + countActiveDevices(account) + '/' + account.device_limit + ' 台'));
    append(document.createTextNode(shortDate(account.created_at) + ' 注册'));
    return node;
  }

  function countActiveDevices(account) {
    var count = 0;
    for (var i = 0; i < devicesCache.length; i++) {
      if (devicesCache[i].account_id === account.id && !devicesCache[i].revoked_at) count++;
    }
    return count;
  }

  function buildExpiry(account, group, now) {
    var node = el('span', 'acct-exp');
    var expires = dateValue(account.expires_at);
    var date = dateText(account.expires_at);
    if (group === '使用中') {
      var remainDays = Math.ceil((expires - now) / 86400000);
      node.textContent = date + ' 到期 · 还剩 ' + remainDays + ' 天';
      if (remainDays <= 7) node.classList.add('warn');
    } else if (group === '已过期') {
      var pastDays = Math.floor((now - expires) / 86400000);
      if (pastDays === 0) node.textContent = date + ' 到期 · 已过期';
      else node.textContent = date + ' 到期 · 已过期 ' + pastDays + ' 天';
      node.classList.add('warn');
    } else {
      node.textContent = '原定 ' + date + ' 到期';
    }
    return node;
  }

  /* 账号页:块头按钮与设备吊销 */
  function buildActions(account, group, card, meta, msg) {
    var box = el('span', 'acct-actions');
    var extendBtn = el('button', 'btn sm', '延期');
    extendBtn.type = 'button';
    extendBtn.addEventListener('click', function () {
      toggleExtend(account, card, meta, msg);
    });
    box.appendChild(extendBtn);
    if (group === '已停用') box.appendChild(buildEnableButton(account, msg));
    else box.appendChild(buildDisableButton(account, msg));
    return box;
  }

  function buildDisableButton(account, msg) {
    var button = el('button', 'btn sm', '停用');
    button.type = 'button';
    button.addEventListener('click', function () {
      if (isBusy(button)) return;
      setBusy(button, true, '正在停用');
      accountAction(account, '/disable', button, '停用', msg);
    });
    return button;
  }

  function buildEnableButton(account, msg) {
    var button = el('button', 'btn sm', '恢复');
    button.type = 'button';
    button.addEventListener('click', function () {
      if (isBusy(button)) return;
      setBusy(button, true, '正在恢复');
      accountAction(account, '/enable', button, '恢复', msg);
    });
    return button;
  }

  function accountAction(account, action, button, label, msg) {
    var path = '/api/accounts/' + encodeURIComponent(account.id) + action;
    request('POST', path, {}).then(function () {
      loadDirectory();
    }, function (error) {
      if (error.code !== 'login_required') setBlockError(msg, error.message);
    }).then(function () {
      setBusy(button, false, label);
    });
  }

  function deviceRows(devices, msg) {
    var rows = el('div', 'rows');
    for (var i = 0; i < devices.length; i++) rows.appendChild(deviceRow(devices[i], msg));
    return rows;
  }

  function deviceRow(device, msg) {
    var row = el('div', 'row dev');
    row.appendChild(el('span', 'label', platformText(device.platform)));
    row.appendChild(el('span', 'val', device.name || ''));
    if (device.last_seen) row.appendChild(el('span', 'rt', '最近在线 ' + shortTime(device.last_seen)));
    else row.appendChild(el('span', 'rt', '没上过线'));
    if (device.revoked_at) {
      row.classList.add('off');
      row.appendChild(el('span', 'badge n', '已吊销'));
    } else {
      row.appendChild(buildRevokeButton(device, row, msg));
    }
    return row;
  }

  function buildRevokeButton(device, row, msg) {
    var button = el('button', 'btn quiet sm danger', '吊销');
    button.type = 'button';
    button.addEventListener('click', function () {
      openRevoke(device, button, row, msg);
    });
    return button;
  }

  function closeConfirm() {
    var restore = openConfirm;
    openConfirm = null;
    if (restore) restore();
  }

  function openRevoke(device, button, row, msg) {
    closeConfirm();
    var box = el('span', 'confirm');
    box.appendChild(document.createTextNode('吊销后这台设备不能再连,不能撤回'));
    var confirmBtn = el('button', 'btn sm danger', '确认吊销');
    confirmBtn.type = 'button';
    var cancelBtn = el('button', 'btn quiet sm', '取消');
    cancelBtn.type = 'button';
    box.appendChild(confirmBtn);
    box.appendChild(cancelBtn);
    if (button.parentNode === row) row.replaceChild(box, button);
    openConfirm = function () {
      if (box.parentNode === row) row.replaceChild(buildRevokeButton(device, row, msg), box);
    };
    cancelBtn.addEventListener('click', function () {
      closeConfirm();
    });
    confirmBtn.addEventListener('click', function () {
      if (isBusy(confirmBtn)) return;
      setBusy(confirmBtn, true, '正在吊销');
      var path = '/api/devices/' + encodeURIComponent(device.id) + '/revoke';
      request('POST', path, {}).then(function () {
        openConfirm = null;
        loadDirectory();
      }, function (error) {
        if (error.code !== 'login_required') setBlockError(msg, error.message);
      }).then(function () {
        setBusy(confirmBtn, false, '确认吊销');
      });
    });
  }

  /* 账号页:延期框 */
  function closeExtend() {
    if (openExtend && openExtend.parentNode) openExtend.parentNode.removeChild(openExtend);
    openExtend = null;
  }

  function toggleExtend(account, card, meta, msg) {
    var sameAccount = !!(openExtend && openExtend.accountId === account.id);
    closeExtend();
    if (sameAccount) return;
    var form = buildExtendForm(account, msg);
    form.accountId = account.id;
    if (meta.nextSibling) card.insertBefore(form, meta.nextSibling);
    else card.appendChild(form);
    openExtend = form;
  }

  function buildExtendForm(account, msg) {
    var form = el('form', 'extend');
    form.noValidate = true;
    form.appendChild(el('span', 'lead', '延长'));
    var input = el('input', 'field num');
    input.type = 'number';
    input.setAttribute('inputmode', 'numeric');
    input.setAttribute('min', '1');
    input.setAttribute('max', '3650');
    input.setAttribute('step', '1');
    input.setAttribute('aria-label', '延长天数');
    input.value = '30';
    var chipsBox = el('span', 'chips');
    chipsBox.setAttribute('role', 'group');
    chipsBox.setAttribute('aria-label', '常用天数');
    var chips = [];
    var values = [7, 30, 90, 365];
    for (var i = 0; i < values.length; i++) {
      (function (value) {
        var chip = el('button', 'chip', value + ' 天');
        chip.type = 'button';
        chip.setAttribute('data-days', String(value));
        chip.setAttribute('aria-pressed', value === 30 ? 'true' : 'false');
        chip.addEventListener('click', function () {
          input.value = String(value);
          syncChips(chips, input.value);
        });
        chipsBox.appendChild(chip);
        chips.push(chip);
      })(values[i]);
    }
    input.addEventListener('input', function () {
      syncChips(chips, input.value);
    });
    form.appendChild(chipsBox);
    form.appendChild(input);
    form.appendChild(el('span', 'lead', '天'));
    var submitBtn = el('button', 'btn sm', '确定');
    submitBtn.type = 'submit';
    var cancelBtn = el('button', 'btn quiet sm', '取消');
    cancelBtn.type = 'button';
    form.appendChild(submitBtn);
    form.appendChild(cancelBtn);
    form.addEventListener('submit', function (event) {
      event.preventDefault();
      if (isBusy(submitBtn)) return;
      var days = parseDays(input.value);
      if (days === null) {
        setBlockError(msg, '天数要填 1 到 3650 的整数');
        input.focus();
        return;
      }
      msg.textContent = '';
      msg.classList.remove('bad');
      setBusy(submitBtn, true, '正在延期');
      var path = '/api/accounts/' + encodeURIComponent(account.id) + '/extend';
      request('POST', path, {days: days}).then(function () {
        loadDirectory();
      }, function (error) {
        if (error.code !== 'login_required') setBlockError(msg, error.message);
      }).then(function () {
        setBusy(submitBtn, false, '确定');
      });
    });
    cancelBtn.addEventListener('click', function () {
      closeExtend();
    });
    return form;
  }

  function init() {
    bindLogin();
    bindLogout();
    bindTabs();
    bindInviteForm();
    bindInvites();
    document.addEventListener('visibilitychange', onVisibilityChange);
    api('GET', '/api/session').then(function (response) {
      var data = response.data || {};
      if (response.ok && data.logged_in) enterApp(data);
      else showLogin('');
    }, function (error) {
      showLogin(error.message);
    });
  }

  init();
})();