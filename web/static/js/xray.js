/* ---------- Настройки Xray ---------- */
const XS_BOOL = ['access_log', 'dns_enable', 'dns_disable_cache', 'block_private', 'block_bittorrent', 'block_ads', 'freedom_fragment'];
const XS_NUM = ['policy_handshake', 'policy_conn_idle', 'policy_uplink_only', 'policy_downlink_only', 'policy_buffer_size'];
const XS_LIST = ['dns_servers', 'block_domains', 'block_ips', 'direct_domains', 'direct_ips'];
const XS_TEXT = ['log_level', 'dns_strategy', 'domain_strategy', 'freedom_strategy', 'routing_extra', 'outbounds_extra', 'raw_patch'];

async function loadXraySettings() {
  const r = await api('GET', '/api/v1/xray/settings');
  if (!r.ok) return;
  const d = r.data;
  XS_BOOL.forEach(k => document.getElementById('xs-' + k).checked = !!d[k]);
  XS_NUM.forEach(k => document.getElementById('xs-' + k).value = d[k] || '');
  XS_LIST.forEach(k => document.getElementById('xs-' + k).value = (d[k] || []).join('\n'));
  XS_TEXT.forEach(k => document.getElementById('xs-' + k).value = d[k] || '');
  const st = await api('GET', '/api/v1/system/status');
  if (st.ok) document.getElementById('xray-core-line').textContent =
    `Ядро: ${st.data.xray_state === 'active' ? 'работает' : (st.data.xray_state === 'not-installed' ? 'не установлено' : 'остановлено')}, версия ${st.data.xray_version}. Изменения проверяются самим Xray перед применением, при ошибке остаётся прежний конфиг.`;
}

async function saveXraySettings() {
  const body = {};
  XS_BOOL.forEach(k => body[k] = document.getElementById('xs-' + k).checked);
  XS_NUM.forEach(k => body[k] = parseInt(document.getElementById('xs-' + k).value) || 0);
  XS_LIST.forEach(k => body[k] = document.getElementById('xs-' + k).value.split('\n').map(x => x.trim()).filter(Boolean));
  XS_TEXT.forEach(k => body[k] = document.getElementById('xs-' + k).value.trim());
  const r = await api('PUT', '/api/v1/xray/settings', body);
  if (r.ok) notify(r); else uiAlert('Xray не принял настройки', String(r.data.error || r.status));
  if (r.ok) { loadXraySettings(); loadSystemStatus(); }
}

// Значения секретных полей в тексте конфига заменяются точками (privateKey, secretKey, preSharedKey, пароли, auth, id).
const maskConfigSecrets = data => JSON.stringify(data, null, 2).replace(/("(?:privateKey|secretKey|preSharedKey|password|auth|id)":\s*")[^"]+(")/g, '$1••••$2');

async function toggleConfigPreview() {
  const pre = document.getElementById('xray-config-preview');
  if (pre.style.display !== 'none') { pre.style.display = 'none'; return; }
  const r = await api('GET', '/api/v1/xray/config');
  const data = r.ok ? r.data : r.data;
  if (r.ok) {
    // ключи REALITY, WireGuard и пароли в предпросмотре скрываем
    pre.textContent = maskConfigSecrets(data);
  } else pre.textContent = 'Ошибка: ' + (data.error || r.status);
  pre.style.display = 'block';
}

async function restartXrayCore() {
  const r = await api('POST', '/api/v1/system/restart-xray');
  await uiAlert(r.ok ? 'Готово' : 'Не получилось', r.ok ? r.data.message : (r.data.error || 'Ошибка'));
  loadSystemStatus();
}
