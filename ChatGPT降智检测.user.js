// ==UserScript==
// @name         ChatGPT 降智检测 Pro
// @namespace    https://chatgpt.com/
// @version      3.4.0
// @description  智能检测当前 IP 风险系数，融合 IPPure 历史风控与 ChatGPT PoW 难度信号，精准评估 ChatGPT 降智风险
// @author       codex5.4 Thinking high
// @match        https://chatgpt.com/*
// @grant        GM_xmlhttpRequest
// @grant        GM_addStyle
// @grant        GM_addElement
// @connect      my.ippure.com
// @connect      chatgpt.com
// @run-at       document-start
// ==/UserScript==

(function () {
  'use strict';
  console.log("🚀 [ChatGPT 降智检测 Pro] 脚本开始运行...");

  // ==================== 历史记录与波动算法引擎 v3 ====================
  const STORAGE_KEY = 'chatgpt_ip_risk_history_v3';
  const MAX_HISTORY = 200;
  const SESSION_GAP_MS = 30 * 60 * 1000;  // 30分钟内算同一会话
  const HOUR_MS = 3600000;
  const DAY_MS = 86400000;

  function loadHistory() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return [];
      const arr = JSON.parse(raw);
      if (!Array.isArray(arr)) return [];
      return arr;
    } catch { return []; }
  }

  function saveHistory(history) {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(history.slice(-MAX_HISTORY)));
    } catch { /* quota exceeded */ }
  }

  // 记录：分数 + 时间戳 + IP
  function addRecord(score, ip) {
    const history = loadHistory();
    history.push({ score, ts: Date.now(), ip: ip || '' });
    saveHistory(history);
    return history;
  }

  // ==================== 模型使用统计 ====================
  const MODEL_USAGE_KEY = 'chatgpt_model_usage_v1';
  const MODEL_USAGE_EVENT = 'chatgpt-model-usage-detected-v2';
  const MODEL_USAGE_ENDPOINTS = ['/backend-api/conversation', '/backend-api/f/conversation'];
  const POW_HISTORY_KEY = 'chatgpt_pow_history_v1';
  const POW_HISTORY_EVENT = 'chatgpt-pow-detected-v1';
  const POW_ENDPOINT_KEYWORDS = ['/backend-api/sentinel/chat-requirements', '/backend-api/sentinel/chat-requirements/prepare', '/sentinel/chat-requirements'];
  const MAX_POW_HISTORY = 160;
  const POW_RECENT_WINDOW_MS = 12 * HOUR_MS;
  const POW_FRESH_MS = 2 * HOUR_MS;
  const recentModelUsage = new Map();
  const recentPowRecords = new Map();
  let modelUsageArmedUntil = 0;

  function loadModelUsage() {
    try {
      const raw = localStorage.getItem(MODEL_USAGE_KEY);
      if (!raw) return {};
      return JSON.parse(raw);
    } catch { return {}; }
  }

  function saveModelUsage(usage) {
    try {
      localStorage.setItem(MODEL_USAGE_KEY, JSON.stringify(usage));
    } catch {}
  }

  function getLocalDateKey(input) {
    const date = input instanceof Date ? new Date(input.getTime()) : new Date(input || Date.now());
    return date.getFullYear()
      + '-' + String(date.getMonth() + 1).padStart(2, '0')
      + '-' + String(date.getDate()).padStart(2, '0');
  }

  function loadPowHistory() {
    try {
      const raw = localStorage.getItem(POW_HISTORY_KEY);
      if (!raw) return [];
      const arr = JSON.parse(raw);
      return Array.isArray(arr) ? arr : [];
    } catch { return []; }
  }

  function savePowHistory(history) {
    try {
      localStorage.setItem(POW_HISTORY_KEY, JSON.stringify(history.slice(-MAX_POW_HISTORY)));
    } catch {}
  }

  function normalizePowDifficulty(value) {
    if (value == null) return '';
    let text = String(value).trim().toLowerCase();
    if (!text) return '';
    if (text.startsWith('0x')) text = text.slice(2);
    text = text.replace(/[^0-9a-f]/g, '');
    if (!text) return '';
    text = text.replace(/^0+/, '');
    return text || '0';
  }

  function powHexToNumber(hex) {
    const normalized = normalizePowDifficulty(hex);
    if (!normalized) return NaN;
    const value = Number.parseInt(normalized, 16);
    return Number.isFinite(value) ? value : NaN;
  }

  function getPowDifficultyDigits(hex) {
    const normalized = normalizePowDifficulty(hex);
    return normalized ? normalized.length : 0;
  }

  function formatPowDifficulty(hex) {
    const normalized = normalizePowDifficulty(hex);
    return normalized ? ('0x' + normalized.toUpperCase()) : '—';
  }

  function buildPowSignature(difficulty, required) {
    return normalizePowDifficulty(difficulty) + '|' + (required === false ? '0' : '1');
  }

  function pruneRecentPowRecords(now) {
    for (const [key, ts] of recentPowRecords.entries()) {
      if ((now - ts) > 10000) recentPowRecords.delete(key);
    }
  }

  function toPowSnapshot(record, now) {
    if (!record || typeof record !== 'object') return null;
    const difficulty = normalizePowDifficulty(record.difficulty);
    const ts = Number(record.ts);
    if (!difficulty || !Number.isFinite(ts) || ts <= 0) return null;
    const value = Number(record.value);
    const numericValue = Number.isFinite(value) && value > 0 ? value : powHexToNumber(difficulty);
    const digits = Number(record.digits) > 0 ? Number(record.digits) : getPowDifficultyDigits(difficulty);
    const currentNow = Number.isFinite(now) ? now : Date.now();
    return {
      difficulty,
      value: Number.isFinite(numericValue) ? numericValue : 0,
      digits,
      ts,
      ageMs: Math.max(0, currentNow - ts),
      label: formatPowDifficulty(difficulty),
      required: record.required !== false,
      source: typeof record.source === 'string' ? record.source : '',
    };
  }

  function getLatestPowSnapshot(maxAgeMs) {
    const now = Date.now();
    const history = loadPowHistory();
    for (let i = history.length - 1; i >= 0; i--) {
      const snapshot = toPowSnapshot(history[i], now);
      if (!snapshot) continue;
      if (Number.isFinite(maxAgeMs) && maxAgeMs > 0 && snapshot.ageMs > maxAgeMs) continue;
      return snapshot;
    }
    return null;
  }

  function isPowRequirementsRequestUrl(url) {
    const normalizedUrl = typeof url === 'string' ? url : String(url || '');
    return POW_ENDPOINT_KEYWORDS.some((keyword) => normalizedUrl.includes(keyword));
  }

  function extractPowDifficultyPayload(payload) {
    if (!payload || typeof payload !== 'object') return null;
    const powObject = payload.proofofwork || payload.proof_of_work || payload.pow || null;
    const difficultyCandidates = [
      powObject && powObject.difficulty,
      payload.difficulty,
      payload.powDifficulty,
    ];
    let difficulty = '';
    for (const candidate of difficultyCandidates) {
      difficulty = normalizePowDifficulty(candidate);
      if (difficulty) break;
    }
    if (!difficulty) return null;

    let required = true;
    const requiredCandidates = [
      powObject && powObject.required,
      payload.required,
      payload.powRequired,
    ];
    for (const candidate of requiredCandidates) {
      if (typeof candidate === 'boolean') {
        required = candidate;
        break;
      }
    }

    return {
      difficulty,
      required,
    };
  }

  function recordPowDifficulty(difficulty, meta) {
    const normalized = normalizePowDifficulty(difficulty);
    if (!normalized) return null;

    const now = Date.now();
    pruneRecentPowRecords(now);

    const required = meta && meta.required === false ? false : true;
    const signature = buildPowSignature(normalized, required);
    const lastSeen = recentPowRecords.get(signature);
    if (lastSeen && (now - lastSeen) < 10000) return null;
    recentPowRecords.set(signature, now);

    const record = {
      difficulty: normalized,
      digits: getPowDifficultyDigits(normalized),
      value: powHexToNumber(normalized),
      ts: now,
      required,
      source: meta && typeof meta.source === 'string' ? meta.source : '',
    };

    const history = loadPowHistory();
    history.push(record);
    savePowHistory(history);
    console.log('[降智检测] PoW difficulty:', record.difficulty, 'digits=' + record.digits, 'source=' + record.source);
    return record;
  }

  function trackPowFromPayload(url, payload, source) {
    const extracted = extractPowDifficultyPayload(payload);
    if (!extracted) return null;
    return recordPowDifficulty(extracted.difficulty, {
      required: extracted.required,
      source: source || (isPowRequirementsRequestUrl(url) ? 'requirements' : 'payload'),
    });
  }

  function recordModelUsage(model, signature) {
    const normalizedModel = normalizeModelName(model);
    if (!normalizedModel) return;
    model = normalizedModel;
    const now = Date.now();
    pruneRecentModelUsage(now);

    const dedupeKey = signature ? ('sig:' + signature) : ('model:' + normalizedModel);
    const dedupeWindow = signature ? 15000 : 1500;
    const lastSeen = recentModelUsage.get(dedupeKey);
    if (lastSeen && (now - lastSeen) < dedupeWindow) return;
    recentModelUsage.set(dedupeKey, now);

    const today = getLocalDateKey();
    const usage = loadModelUsage();
    if (!usage[today]) usage[today] = {};
    if (!usage[today][normalizedModel]) usage[today][normalizedModel] = 0;
    usage[today][normalizedModel]++;
    saveModelUsage(usage);
    console.log('[降智检测] 模型使用记录:', model, today, usage[today][model] + '次');
    try { updateModelUsageMini(); } catch {}
  }

  function getTodayUsage() {
    const today = getLocalDateKey();
    const usage = loadModelUsage();
    return usage[today] || {};
  }

  function getTodayTotal() {
    const todayUsage = getTodayUsage();
    return Object.values(todayUsage).reduce((a, b) => a + b, 0);
  }

  function normalizeModelName(model) {
    return typeof model === 'string' ? model.trim() : '';
  }

  function pruneRecentModelUsage(now) {
    for (const [key, ts] of recentModelUsage.entries()) {
      if ((now - ts) > 15000) recentModelUsage.delete(key);
    }
  }

  function hashString(input) {
    let hash = 2166136261;
    for (let i = 0; i < input.length; i++) {
      hash ^= input.charCodeAt(i);
      hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
    }
    return (hash >>> 0).toString(36);
  }

  function buildUsageSignature(url, bodyText) {
    if (typeof bodyText !== 'string' || !bodyText) return '';
    return hashString(String(url || '') + '|' + bodyText);
  }

  function armModelUsageTracking() {
    modelUsageArmedUntil = Date.now() + 15000;
  }

  function consumeModelUsageTrackingArm() {
    modelUsageArmedUntil = 0;
  }

  function isModelUsageTrackingArmed() {
    return Date.now() <= modelUsageArmedUntil;
  }

  function hasMeaningfulPromptContent(value) {
    if (typeof value === 'string') return value.trim().length > 0;
    if (Array.isArray(value)) return value.some(hasMeaningfulPromptContent);
    if (!value || typeof value !== 'object') return false;

    const directKeys = ['text', 'prompt', 'content', 'transcript', 'caption', 'name', 'title', 'asset_pointer', 'uri', 'url', 'file_id'];
    for (const key of directKeys) {
      if (typeof value[key] === 'string' && value[key].trim()) return true;
    }

    if (Array.isArray(value.parts) && value.parts.some(hasMeaningfulPromptContent)) return true;
    if (Array.isArray(value.items) && value.items.some(hasMeaningfulPromptContent)) return true;
    if (Array.isArray(value.attachments) && value.attachments.length > 0) return true;
    if (Array.isArray(value.files) && value.files.length > 0) return true;
    if (value.content && hasMeaningfulPromptContent(value.content)) return true;
    return false;
  }

  function isUserRoleMessage(message) {
    if (!message || typeof message !== 'object') return false;
    const roleCandidates = [message?.author?.role, message?.role, message?.metadata?.role];
    return roleCandidates.some((role) => normalizeModelName(role).toLowerCase() === 'user');
  }

  function hasUserMessageInList(messages) {
    if (!Array.isArray(messages)) return false;
    return messages.some((message) => {
      if (!isUserRoleMessage(message)) return false;
      return [
        message?.content,
        message?.content?.parts,
        message?.text,
        message?.parts,
        message?.attachments,
        message?.files,
      ].some(hasMeaningfulPromptContent);
    });
  }

  function hasUserSubmissionPayload(payload) {
    if (!payload || typeof payload !== 'object') return false;
    if (hasUserMessageInList(payload.messages)) return true;
    if (hasUserMessageInList(payload?.conversation?.messages)) return true;

    return [
      payload.prompt,
      payload.text,
      payload.input,
      payload.message,
      payload.user_input,
      payload?.conversation?.prompt,
      payload?.conversation?.input,
    ].some(hasMeaningfulPromptContent);
  }

  function isComposerElement(target) {
    return !!(target && target.closest && target.closest('textarea, [contenteditable="true"]'));
  }

  function isLikelySendButton(target) {
    const button = target && target.closest ? target.closest('button, [role="button"]') : null;
    if (!button) return false;

    const marker = [
      button.getAttribute('type') || '',
      button.getAttribute('aria-label') || '',
      button.getAttribute('data-testid') || '',
      button.textContent || '',
    ].join(' ').toLowerCase();

    if (button.getAttribute('type') === 'submit') return true;
    return /send|发送|submit/.test(marker);
  }

  function installModelUsageArmListeners() {
    if (window.__chatgptModelUsageArmListenersInstalled) return;
    window.__chatgptModelUsageArmListenersInstalled = true;

    document.addEventListener('submit', (event) => {
      if (event.target && typeof event.target.closest === 'function') armModelUsageTracking();
    }, true);

    document.addEventListener('keydown', (event) => {
      if (event.key !== 'Enter' || event.shiftKey || event.isComposing) return;
      if (isComposerElement(event.target)) armModelUsageTracking();
    }, true);

    document.addEventListener('click', (event) => {
      if (isLikelySendButton(event.target)) armModelUsageTracking();
    }, true);
  }

  function extractModelFromPayload(payload) {
    if (!payload || typeof payload !== 'object') return '';
    const candidates = [
      payload.model,
      payload.model_slug,
      payload.requested_model,
      payload.requested_model_slug,
      payload.default_model,
      payload?.conversation_mode?.model,
      payload?.conversation_mode?.model_slug,
    ];
    for (const candidate of candidates) {
      const model = normalizeModelName(candidate);
      if (model) return model;
    }
    return '';
  }

  function isConversationRequestUrl(url) {
    const normalizedUrl = typeof url === 'string' ? url : String(url || '');
    return MODEL_USAGE_ENDPOINTS.some((endpoint) => normalizedUrl.includes(endpoint));
  }

  function trackModelUsageFromBody(url, bodyText, signature) {
    if (!isConversationRequestUrl(url) || typeof bodyText !== 'string' || !bodyText) return;
    try {
      const parsed = JSON.parse(bodyText);
      if (!isModelUsageTrackingArmed() || !hasUserSubmissionPayload(parsed)) return;
      const model = extractModelFromPayload(parsed);
      if (model) {
        consumeModelUsageTrackingArm();
        recordModelUsage(model, signature || buildUsageSignature(url, bodyText));
      }
    } catch {}
  }

  function updateModelUsageMini() {
    const el = document.getElementById('model-usage-today');
    if (el) {
      const total = getTodayTotal();
      const todayUsage = getTodayUsage();
      const models = Object.keys(todayUsage);
      el.textContent = '今日已使用 ' + total + ' 次' + (models.length > 0 ? '（' + models.length + ' 个模型）' : '');
    }
  }

  // ==================== Fetch 拦截：追踪模型使用 ====================
  function installLocalModelUsageTracker() {
    if (window.__chatgptModelUsageLocalHookInstalled) return;
    window.__chatgptModelUsageLocalHookInstalled = true;

    const _origFetch = window.fetch;
    if (typeof _origFetch === 'function') {
      window.fetch = function(input, init) {
        try {
          const url = typeof input === 'string'
            ? input
            : (input && typeof input.url === 'string' ? input.url : String(input || ''));

          if (isConversationRequestUrl(url)) {
            if (init && typeof init.body === 'string') {
              trackModelUsageFromBody(url, init.body, buildUsageSignature(url, init.body));
            } else if (typeof Request !== 'undefined' && input instanceof Request) {
              input.clone().text().then((bodyText) => {
                trackModelUsageFromBody(url, bodyText, buildUsageSignature(url, bodyText));
              }).catch(() => {});
            }
          }
        } catch {}
        return _origFetch.apply(this, arguments);
      };
    }

    if (window.XMLHttpRequest && window.XMLHttpRequest.prototype) {
      const origOpen = window.XMLHttpRequest.prototype.open;
      const origSend = window.XMLHttpRequest.prototype.send;

      window.XMLHttpRequest.prototype.open = function(method, url) {
        try {
          this.__chatgptModelUsageUrl = typeof url === 'string' ? url : String(url || '');
        } catch {}
        return origOpen.apply(this, arguments);
      };

      window.XMLHttpRequest.prototype.send = function(body) {
        try {
          const url = this.__chatgptModelUsageUrl || '';
          if (isConversationRequestUrl(url) && typeof body === 'string') {
            trackModelUsageFromBody(url, body, buildUsageSignature(url, body));
          }
        } catch {}
        return origSend.apply(this, arguments);
      };
    }
  }

  function injectPageModelUsageTracker() {
    if (window.__chatgptModelUsagePageBridgeInstalled) return;
    window.__chatgptModelUsagePageBridgeInstalled = true;

    const install = () => {
      const scriptText = `
        (() => {
          const EVENT_NAME = ${JSON.stringify(MODEL_USAGE_EVENT)};
          const ENDPOINTS = ${JSON.stringify(MODEL_USAGE_ENDPOINTS)};
          const FLAG = '__chatgptModelUsagePageHookInstalled';
          if (window[FLAG]) return;
          window[FLAG] = true;

          function normalizeModelName(model) {
            return typeof model === 'string' ? model.trim() : '';
          }

          function hashString(input) {
            let hash = 2166136261;
            for (let i = 0; i < input.length; i++) {
              hash ^= input.charCodeAt(i);
              hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
            }
            return (hash >>> 0).toString(36);
          }

          function buildUsageSignature(url, bodyText) {
            if (typeof bodyText !== 'string' || !bodyText) return '';
            return hashString(String(url || '') + '|' + bodyText);
          }

          let modelUsageArmedUntil = 0;

          function armModelUsageTracking() {
            modelUsageArmedUntil = Date.now() + 15000;
          }

          function consumeModelUsageTrackingArm() {
            modelUsageArmedUntil = 0;
          }

          function isModelUsageTrackingArmed() {
            return Date.now() <= modelUsageArmedUntil;
          }

          function hasMeaningfulPromptContent(value) {
            if (typeof value === 'string') return value.trim().length > 0;
            if (Array.isArray(value)) return value.some(hasMeaningfulPromptContent);
            if (!value || typeof value !== 'object') return false;

            const directKeys = ['text', 'prompt', 'content', 'transcript', 'caption', 'name', 'title', 'asset_pointer', 'uri', 'url', 'file_id'];
            for (const key of directKeys) {
              if (typeof value[key] === 'string' && value[key].trim()) return true;
            }

            if (Array.isArray(value.parts) && value.parts.some(hasMeaningfulPromptContent)) return true;
            if (Array.isArray(value.items) && value.items.some(hasMeaningfulPromptContent)) return true;
            if (Array.isArray(value.attachments) && value.attachments.length > 0) return true;
            if (Array.isArray(value.files) && value.files.length > 0) return true;
            if (value.content && hasMeaningfulPromptContent(value.content)) return true;
            return false;
          }

          function isUserRoleMessage(message) {
            if (!message || typeof message !== 'object') return false;
            const roleCandidates = [
              message && message.author && message.author.role,
              message && message.role,
              message && message.metadata && message.metadata.role,
            ];
            return roleCandidates.some((role) => normalizeModelName(role).toLowerCase() === 'user');
          }

          function hasUserMessageInList(messages) {
            if (!Array.isArray(messages)) return false;
            return messages.some((message) => {
              if (!isUserRoleMessage(message)) return false;
              return [
                message && message.content,
                message && message.content && message.content.parts,
                message && message.text,
                message && message.parts,
                message && message.attachments,
                message && message.files,
              ].some(hasMeaningfulPromptContent);
            });
          }

          function hasUserSubmissionPayload(payload) {
            if (!payload || typeof payload !== 'object') return false;
            if (hasUserMessageInList(payload.messages)) return true;
            if (payload.conversation && hasUserMessageInList(payload.conversation.messages)) return true;

            return [
              payload.prompt,
              payload.text,
              payload.input,
              payload.message,
              payload.user_input,
              payload.conversation && payload.conversation.prompt,
              payload.conversation && payload.conversation.input,
            ].some(hasMeaningfulPromptContent);
          }

          function isComposerElement(target) {
            return !!(target && target.closest && target.closest('textarea, [contenteditable="true"]'));
          }

          function isLikelySendButton(target) {
            const button = target && target.closest ? target.closest('button, [role="button"]') : null;
            if (!button) return false;

            const marker = [
              button.getAttribute('type') || '',
              button.getAttribute('aria-label') || '',
              button.getAttribute('data-testid') || '',
              button.textContent || '',
            ].join(' ').toLowerCase();

            if (button.getAttribute('type') === 'submit') return true;
            return /send|发送|submit/.test(marker);
          }

          function installModelUsageArmListeners() {
            if (window.__chatgptModelUsagePageArmInstalled) return;
            window.__chatgptModelUsagePageArmInstalled = true;

            document.addEventListener('submit', (event) => {
              if (event.target && typeof event.target.closest === 'function') armModelUsageTracking();
            }, true);

            document.addEventListener('keydown', (event) => {
              if (event.key !== 'Enter' || event.shiftKey || event.isComposing) return;
              if (isComposerElement(event.target)) armModelUsageTracking();
            }, true);

            document.addEventListener('click', (event) => {
              if (isLikelySendButton(event.target)) armModelUsageTracking();
            }, true);
          }

          function isConversationRequestUrl(url) {
            const normalizedUrl = typeof url === 'string' ? url : String(url || '');
            return ENDPOINTS.some((endpoint) => normalizedUrl.includes(endpoint));
          }

          function extractModelFromPayload(payload) {
            if (!payload || typeof payload !== 'object') return '';
            const candidates = [
              payload.model,
              payload.model_slug,
              payload.requested_model,
              payload.requested_model_slug,
              payload.default_model,
              payload && payload.conversation_mode && payload.conversation_mode.model,
              payload && payload.conversation_mode && payload.conversation_mode.model_slug,
            ];
            for (const candidate of candidates) {
              const model = normalizeModelName(candidate);
              if (model) return model;
            }
            return '';
          }

          function emit(model, signature) {
            const normalizedModel = normalizeModelName(model);
            if (!normalizedModel) return;
            window.dispatchEvent(new CustomEvent(EVENT_NAME, {
              detail: { model: normalizedModel, signature: signature || '' }
            }));
          }

          function trackModelUsageFromBody(url, bodyText) {
            if (!isConversationRequestUrl(url) || typeof bodyText !== 'string' || !bodyText) return;
            try {
              const parsed = JSON.parse(bodyText);
              if (!isModelUsageTrackingArmed() || !hasUserSubmissionPayload(parsed)) return;
              const model = extractModelFromPayload(parsed);
              if (model) {
                consumeModelUsageTrackingArm();
                emit(model, buildUsageSignature(url, bodyText));
              }
            } catch {}
          }

          installModelUsageArmListeners();

          const originalFetch = window.fetch;
          if (typeof originalFetch === 'function') {
            window.fetch = function(input, init) {
              try {
                const url = typeof input === 'string'
                  ? input
                  : (input && typeof input.url === 'string' ? input.url : String(input || ''));

                if (isConversationRequestUrl(url)) {
                  if (init && typeof init.body === 'string') {
                    trackModelUsageFromBody(url, init.body);
                  } else if (typeof Request !== 'undefined' && input instanceof Request) {
                    input.clone().text().then((bodyText) => {
                      trackModelUsageFromBody(url, bodyText);
                    }).catch(() => {});
                  }
                }
              } catch {}
              return originalFetch.apply(this, arguments);
            };
          }

          if (window.XMLHttpRequest && window.XMLHttpRequest.prototype) {
            const originalOpen = window.XMLHttpRequest.prototype.open;
            const originalSend = window.XMLHttpRequest.prototype.send;

            window.XMLHttpRequest.prototype.open = function(method, url) {
              try {
                this.__chatgptModelUsageUrl = typeof url === 'string' ? url : String(url || '');
              } catch {}
              return originalOpen.apply(this, arguments);
            };

            window.XMLHttpRequest.prototype.send = function(body) {
              try {
                const url = this.__chatgptModelUsageUrl || '';
                if (isConversationRequestUrl(url) && typeof body === 'string') {
                  trackModelUsageFromBody(url, body);
                }
              } catch {}
              return originalSend.apply(this, arguments);
            };
          }
        })();
      `;

      try {
        if (typeof GM_addElement === 'function') {
          GM_addElement(document.documentElement || document.head || document.body, 'script', {
            textContent: scriptText,
          });
          return;
        }
      } catch {}

      try {
        const script = document.createElement('script');
        script.textContent = scriptText;
        (document.documentElement || document.head || document.body).appendChild(script);
        script.remove();
      } catch {}
    };

    if (document.documentElement || document.head || document.body) {
      install();
    } else {
      document.addEventListener('readystatechange', install, { once: true });
    }
  }

  function installModelUsageTracker() {
    if (window.__chatgptModelUsageTrackerInstalled) return;
    window.__chatgptModelUsageTrackerInstalled = true;

    window.addEventListener(MODEL_USAGE_EVENT, (event) => {
      const detail = event && event.detail ? event.detail : {};
      recordModelUsage(detail.model, detail.signature);
    });

    installModelUsageArmListeners();
    installLocalModelUsageTracker();
    injectPageModelUsageTracker();
  }

  installModelUsageTracker();

  function inspectPowResponsePayload(url, payload, source) {
    try {
      trackPowFromPayload(url, payload, source);
    } catch {}
  }

  function inspectPowFetchResponse(url, response, source) {
    if (!isPowRequirementsRequestUrl(url) || !response || typeof response.clone !== 'function') return;
    response.clone().json().then((payload) => {
      inspectPowResponsePayload(url, payload, source);
    }).catch(() => {});
  }

  function installLocalPowTracker() {
    if (window.__chatgptPowLocalHookInstalled) return;
    window.__chatgptPowLocalHookInstalled = true;

    const originalFetch = window.fetch;
    if (typeof originalFetch === 'function') {
      window.fetch = function(input, init) {
        let url = '';
        try {
          url = typeof input === 'string'
            ? input
            : (input && typeof input.url === 'string' ? input.url : String(input || ''));
        } catch {}

        const result = originalFetch.apply(this, arguments);
        if (isPowRequirementsRequestUrl(url) && result && typeof result.then === 'function') {
          result.then((response) => {
            inspectPowFetchResponse(url, response, 'fetch');
          }).catch(() => {});
        }
        return result;
      };
    }

    if (window.XMLHttpRequest && window.XMLHttpRequest.prototype) {
      const originalOpen = window.XMLHttpRequest.prototype.open;
      const originalSend = window.XMLHttpRequest.prototype.send;

      window.XMLHttpRequest.prototype.open = function(method, url) {
        try {
          this.__chatgptPowUrl = typeof url === 'string' ? url : String(url || '');
        } catch {}
        return originalOpen.apply(this, arguments);
      };

      window.XMLHttpRequest.prototype.send = function() {
        try {
          if (!this.__chatgptPowLoadListenerInstalled) {
            this.__chatgptPowLoadListenerInstalled = true;
            this.addEventListener('load', () => {
              try {
                const url = this.__chatgptPowUrl || '';
                if (!isPowRequirementsRequestUrl(url)) return;

                let payload = null;
                if (this.responseType === 'json' && this.response && typeof this.response === 'object') {
                  payload = this.response;
                } else if (!this.responseType || this.responseType === 'text') {
                  payload = JSON.parse(this.responseText || '');
                }

                if (payload) inspectPowResponsePayload(url, payload, 'xhr');
              } catch {}
            });
          }
        } catch {}
        return originalSend.apply(this, arguments);
      };
    }
  }

  function injectPagePowTracker() {
    if (window.__chatgptPowPageBridgeInstalled) return;
    window.__chatgptPowPageBridgeInstalled = true;

    const install = () => {
      const scriptText = `
        (() => {
          const EVENT_NAME = ${JSON.stringify(POW_HISTORY_EVENT)};
          const ENDPOINTS = ${JSON.stringify(POW_ENDPOINT_KEYWORDS)};
          const FLAG = '__chatgptPowPageHookInstalled';
          if (window[FLAG]) return;
          window[FLAG] = true;

          function normalizePowDifficulty(value) {
            if (value == null) return '';
            let text = String(value).trim().toLowerCase();
            if (!text) return '';
            if (text.startsWith('0x')) text = text.slice(2);
            text = text.replace(/[^0-9a-f]/g, '');
            if (!text) return '';
            text = text.replace(/^0+/, '');
            return text || '0';
          }

          function isPowRequirementsRequestUrl(url) {
            const normalizedUrl = typeof url === 'string' ? url : String(url || '');
            return ENDPOINTS.some((keyword) => normalizedUrl.includes(keyword));
          }

          function extractPowDifficultyPayload(payload) {
            if (!payload || typeof payload !== 'object') return null;
            const powObject = payload.proofofwork || payload.proof_of_work || payload.pow || null;
            const difficultyCandidates = [
              powObject && powObject.difficulty,
              payload.difficulty,
              payload.powDifficulty,
            ];
            let difficulty = '';
            for (const candidate of difficultyCandidates) {
              difficulty = normalizePowDifficulty(candidate);
              if (difficulty) break;
            }
            if (!difficulty) return null;

            let required = true;
            const requiredCandidates = [
              powObject && powObject.required,
              payload.required,
              payload.powRequired,
            ];
            for (const candidate of requiredCandidates) {
              if (typeof candidate === 'boolean') {
                required = candidate;
                break;
              }
            }

            return { difficulty, required };
          }

          function emit(detail) {
            if (!detail || !detail.difficulty) return;
            window.dispatchEvent(new CustomEvent(EVENT_NAME, { detail }));
          }

          function inspectPayload(url, payload, source) {
            const extracted = extractPowDifficultyPayload(payload);
            if (!extracted) return;
            emit({
              difficulty: extracted.difficulty,
              required: extracted.required,
              source: source || 'page',
            });
          }

          const originalFetch = window.fetch;
          if (typeof originalFetch === 'function') {
            window.fetch = function(input, init) {
              let url = '';
              try {
                url = typeof input === 'string'
                  ? input
                  : (input && typeof input.url === 'string' ? input.url : String(input || ''));
              } catch {}

              const result = originalFetch.apply(this, arguments);
              if (isPowRequirementsRequestUrl(url) && result && typeof result.then === 'function') {
                result.then((response) => {
                  try {
                    if (!response || typeof response.clone !== 'function') return;
                    response.clone().json().then((payload) => {
                      inspectPayload(url, payload, 'page-fetch');
                    }).catch(() => {});
                  } catch {}
                }).catch(() => {});
              }
              return result;
            };
          }

          if (window.XMLHttpRequest && window.XMLHttpRequest.prototype) {
            const originalOpen = window.XMLHttpRequest.prototype.open;
            const originalSend = window.XMLHttpRequest.prototype.send;

            window.XMLHttpRequest.prototype.open = function(method, url) {
              try {
                this.__chatgptPowUrl = typeof url === 'string' ? url : String(url || '');
              } catch {}
              return originalOpen.apply(this, arguments);
            };

            window.XMLHttpRequest.prototype.send = function() {
              try {
                if (!this.__chatgptPowLoadListenerInstalled) {
                  this.__chatgptPowLoadListenerInstalled = true;
                  this.addEventListener('load', () => {
                    try {
                      const url = this.__chatgptPowUrl || '';
                      if (!isPowRequirementsRequestUrl(url)) return;

                      let payload = null;
                      if (this.responseType === 'json' && this.response && typeof this.response === 'object') {
                        payload = this.response;
                      } else if (!this.responseType || this.responseType === 'text') {
                        payload = JSON.parse(this.responseText || '');
                      }

                      if (payload) inspectPayload(url, payload, 'page-xhr');
                    } catch {}
                  });
                }
              } catch {}
              return originalSend.apply(this, arguments);
            };
          }
        })();
      `;

      try {
        if (typeof GM_addElement === 'function') {
          GM_addElement(document.documentElement || document.head || document.body, 'script', {
            textContent: scriptText,
          });
          return;
        }
      } catch {}

      try {
        const script = document.createElement('script');
        script.textContent = scriptText;
        (document.documentElement || document.head || document.body).appendChild(script);
        script.remove();
      } catch {}
    };

    if (document.documentElement || document.head || document.body) {
      install();
    } else {
      document.addEventListener('readystatechange', install, { once: true });
    }
  }

  function installPowTracker() {
    if (window.__chatgptPowTrackerInstalled) return;
    window.__chatgptPowTrackerInstalled = true;

    window.addEventListener(POW_HISTORY_EVENT, (event) => {
      const detail = event && event.detail ? event.detail : {};
      recordPowDifficulty(detail.difficulty, {
        required: detail.required,
        source: detail.source || 'event',
      });
    });

    installLocalPowTracker();
    injectPagePowTracker();
  }

  installPowTracker();

  // 风险区间 (0-5)
  function scoreToZone(s) {
    if (s <= 15) return 0;
    if (s <= 25) return 1;
    if (s <= 40) return 2;
    if (s <= 50) return 3;
    if (s <= 60) return 4;
    return 5;
  }

  // 区间名称
  function zoneName(z) {
    return ['纯净','良好','中等偏好','中等偏下','差','极危'][z] || '未知';
  }

  function clamp(value, min, max) {
    return Math.min(max, Math.max(min, value));
  }

  function round1(value) {
    return Math.round(value * 10) / 10;
  }

  function average(values) {
    return values.length ? values.reduce((sum, value) => sum + value, 0) / values.length : 0;
  }

  function calcEMA(data, span) {
    if (!data.length) return 0;
    const k = 2 / (span + 1);
    let ema = data[0];
    for (let i = 1; i < data.length; i++) {
      ema = data[i] * k + ema * (1 - k);
    }
    return ema;
  }

  function calcMedian(data) {
    if (!data.length) return 0;
    const sorted = [...data].sort((a, b) => a - b);
    const mid = Math.floor(sorted.length / 2);
    return sorted.length % 2
      ? sorted[mid]
      : (sorted[mid - 1] + sorted[mid]) / 2;
  }

  function calcPercentile(data, percentile) {
    if (!data.length) return 0;
    const sorted = [...data].sort((a, b) => a - b);
    const pos = clamp(percentile, 0, 1) * (sorted.length - 1);
    const lower = Math.floor(pos);
    const upper = Math.ceil(pos);
    if (lower === upper) return sorted[lower];
    return sorted[lower] + (sorted[upper] - sorted[lower]) * (pos - lower);
  }

  function calcMAD(data) {
    if (!data.length) return 0;
    const median = calcMedian(data);
    return calcMedian(data.map(value => Math.abs(value - median)));
  }

  function calcSlope(data) {
    if (data.length < 2) return 0;
    let sumX = 0;
    let sumY = 0;
    let sumXY = 0;
    let sumXX = 0;
    for (let i = 0; i < data.length; i++) {
      sumX += i;
      sumY += data[i];
      sumXY += i * data[i];
      sumXX += i * i;
    }
    const denominator = data.length * sumXX - sumX * sumX;
    if (!denominator) return 0;
    return (data.length * sumXY - sumX * sumY) / denominator;
  }

  function normalizeHistoryRecords(history) {
    if (!Array.isArray(history)) return [];
    return history
      .map((record) => {
        const score = clamp(Number(record?.score), 0, 100);
        const ts = Number(record?.ts);
        if (!Number.isFinite(score) || !Number.isFinite(ts) || ts <= 0) return null;
        return {
          score,
          ts,
          ip: typeof record?.ip === 'string' ? record.ip.trim() : '',
        };
      })
      .filter(Boolean)
      .sort((a, b) => a.ts - b.ts);
  }

  function buildSessions(history) {
    const sessions = [];
    for (const record of history) {
      const lastSession = sessions[sessions.length - 1];
      const sameIP = lastSession && lastSession.ip === record.ip;
      const withinGap = lastSession && (record.ts - lastSession.endTs) < SESSION_GAP_MS;

      if (sameIP && withinGap) {
        lastSession.endTs = record.ts;
        lastSession.lastScore = record.score;
        lastSession.sum += record.score;
        lastSession.count += 1;
        lastSession.max = Math.max(lastSession.max, record.score);
        lastSession.min = Math.min(lastSession.min, record.score);
        lastSession.raw.push(record.score);
      } else {
        sessions.push({
          ip: record.ip,
          startTs: record.ts,
          endTs: record.ts,
          lastScore: record.score,
          sum: record.score,
          count: 1,
          max: record.score,
          min: record.score,
          raw: [record.score],
        });
      }
    }

    return sessions.map((session) => {
      const sessionAvg = session.sum / session.count;
      const sessionUpper = calcPercentile(session.raw, 0.75);
      const score = session.count === 1
        ? session.lastScore
        : round1(clamp(
          session.lastScore * 0.55
          + sessionAvg * 0.25
          + sessionUpper * 0.20,
          0,
          100
        ));

      return {
        score,
        ts: session.endTs,
        ip: session.ip,
        lastScore: session.lastScore,
        sessionAvg: round1(sessionAvg),
        sessionPeak: session.max,
        sessionLow: session.min,
        count: session.count,
        durationMs: session.endTs - session.startTs,
      };
    });
  }

  function getPowStrength(value) {
    if (!Number.isFinite(value) || value <= 0) return 0;
    const log16 = Math.log(value + 1) / Math.log(16);
    return clamp(((log16 - 2) / 3) * 100, 0, 100);
  }

  function analyzePowHistory(powSnapshot, now) {
    const allPowHistory = loadPowHistory()
      .map((record) => toPowSnapshot(record, now))
      .filter(Boolean)
      .sort((a, b) => a.ts - b.ts);

    let recentPowHistory = allPowHistory.filter((item) => item.ageMs <= POW_RECENT_WINDOW_MS);
    if (!recentPowHistory.length) recentPowHistory = allPowHistory.slice(-8);
    else recentPowHistory = recentPowHistory.slice(-8);

    const currentPow = powSnapshot && powSnapshot.difficulty
      ? toPowSnapshot(powSnapshot, now)
      : (recentPowHistory.length ? recentPowHistory[recentPowHistory.length - 1] : null);

    if (!currentPow) {
      return {
        powAvailable: false,
        powFresh: false,
        powRisk: 50,
        powLowRatio: 0,
        powHighRatio: 0,
        powTrend: 0,
        powSampleCount: 0,
        powCurrentLabel: '—',
        powCurrentDifficulty: '',
        powCurrentDigits: 0,
        powCurrentAgeMinutes: null,
        powCurrentStrength: 0,
      };
    }

    const strengthSeries = recentPowHistory.map((item) => getPowStrength(item.value));
    const digitSeries = recentPowHistory.map((item) => item.digits);
    const strengthMedian = calcMedian(strengthSeries);
    const currentStrength = getPowStrength(currentPow.value);
    const lowRatio = recentPowHistory.length
      ? recentPowHistory.filter((item) => item.digits <= 3).length / recentPowHistory.length
      : 0;
    const highRatio = recentPowHistory.length
      ? recentPowHistory.filter((item) => item.digits >= 5).length / recentPowHistory.length
      : 0;

    let strengthTrend = 0;
    if (strengthSeries.length >= 4) {
      const split = Math.floor(strengthSeries.length / 2);
      strengthTrend = average(strengthSeries.slice(-Math.max(1, strengthSeries.length - split)))
        - average(strengthSeries.slice(0, Math.max(1, split)));
    } else if (strengthSeries.length >= 2) {
      strengthTrend = strengthSeries[strengthSeries.length - 1] - strengthSeries[0];
    }

    const digitAvg = average(digitSeries);
    const digitStd = digitSeries.length > 1
      ? Math.sqrt(average(digitSeries.map((digit) => (digit - digitAvg) ** 2)))
      : 0;

    let powRisk = 100 - (currentStrength * 0.58 + strengthMedian * 0.42);
    powRisk += clamp(lowRatio * 20 - highRatio * 8, -8, 12);
    powRisk += clamp(digitStd * 6, 0, 10);
    powRisk -= clamp(strengthTrend * 0.18, -8, 8);
    if (currentPow.digits <= 3) powRisk += 6;
    else if (currentPow.digits >= 5) powRisk -= 4;
    powRisk = Math.round(clamp(powRisk, 0, 100));

    return {
      powAvailable: true,
      powFresh: currentPow.ageMs <= POW_FRESH_MS,
      powRisk,
      powLowRatio: round1(lowRatio * 100),
      powHighRatio: round1(highRatio * 100),
      powTrend: round1(strengthTrend),
      powSampleCount: recentPowHistory.length,
      powCurrentLabel: currentPow.label,
      powCurrentDifficulty: currentPow.difficulty,
      powCurrentDigits: currentPow.digits,
      powCurrentAgeMinutes: Math.round(currentPow.ageMs / 60000),
      powCurrentStrength: Math.round(currentStrength),
    };
  }

  /**
   * 核心波动分析算法 v3
   *
   * 升级要点:
   * 1. 时间衰减加权 —— 越新的记录权重越高（指数衰减 λ=24h半衰期）
   * 2. IP切换检测 —— 识别换节点行为，分离不同IP的评估
   * 3. 会话聚类 —— 30min内多次刷新只算一个数据点，防刷新刷数据
   * 4. EMA双线交叉 —— 短期EMA vs 长期EMA，类股票金叉死叉判趋势
   * 5. 连续恶化模式检测 —— 识别"锯齿波"（忽高忽低）和"阶梯恶化"
   * 6. 置信度系统 —— 数据越多、时间跨度越长，判定越可信
   * 7. 综合风险评分 —— 0-100 最终归一化评分
   */
  function analyzeHistoryLegacy(currentScore, currentIP) {
    const allHistory = loadHistory();
    const now = Date.now();

    // ===== 会话去重：30min内多条取最后一条 =====
    const sessions = [];
    for (let i = 0; i < allHistory.length; i++) {
      const rec = allHistory[i];
      const lastSession = sessions[sessions.length - 1];
      if (lastSession && (rec.ts - lastSession.ts) < SESSION_GAP_MS) {
        // 同一会话，更新为最新分数
        sessions[sessions.length - 1] = rec;
      } else {
        sessions.push({ ...rec });
      }
    }
    const n = sessions.length;

    // 数据量不足
    if (n < 3) {
      const baseLevel = currentScore <= 25 ? 'safe' : (currentScore <= 50 ? 'warn' : 'danger');
      return {
        verdict: '📊 数据积累中（' + n + '/3），需更多访问以启动深度分析',
        verdictLevel: baseLevel,
        avgScore: currentScore,
        weightedAvg: currentScore,
        stdDev: 0,
        volatility: 0,
        zoneJumps: 0,
        trend: '—',
        trendDelta: 0,
        totalRecords: allHistory.length,
        totalSessions: n,
        stability: 50,
        confidence: Math.round(n / 3 * 30),
        compositeRisk: currentScore,
        ipSwitches: 0,
        currentIPHistory: [],
        emaShort: currentScore,
        emaLong: currentScore,
        sawtoothDetected: false,
        stairDetected: false,
        peakScore: currentScore,
        recentPeakScore: currentScore,
      };
    }

    const scores = sessions.map(h => h.score);
    const times = sessions.map(h => h.ts);

    // ===== 1. 基础统计 =====
    const avg = scores.reduce((a, b) => a + b, 0) / n;
    const variance = scores.reduce((sum, s) => sum + (s - avg) ** 2, 0) / n;
    const stdDev = Math.sqrt(variance);
    const volatility = Math.min(100, Math.round((stdDev / 50) * 100));

    // ===== 2. 时间衰减加权平均 =====
    // 半衰期 24h：24小时前的记录权重减半
    const HALF_LIFE = DAY_MS;
    const lambda = Math.LN2 / HALF_LIFE;
    let weightedSum = 0, weightTotal = 0;
    for (let i = 0; i < n; i++) {
      const age = now - times[i];
      const w = Math.exp(-lambda * age);
      weightedSum += scores[i] * w;
      weightTotal += w;
    }
    const weightedAvg = weightTotal > 0 ? weightedSum / weightTotal : avg;

    // ===== 3. EMA 双线 =====
    // 短期 EMA (span=5)，长期 EMA (span=15)
    function calcEMA(data, span) {
      const k = 2 / (span + 1);
      let ema = data[0];
      for (let i = 1; i < data.length; i++) {
        ema = data[i] * k + ema * (1 - k);
      }
      return ema;
    }
    const emaShort = Math.round(calcEMA(scores, Math.min(5, n)) * 10) / 10;
    const emaLong = Math.round(calcEMA(scores, Math.min(15, n)) * 10) / 10;

    // ===== 4. 区间跳跃 =====
    let zoneJumps = 0;
    for (let i = 1; i < n; i++) {
      if (scoreToZone(scores[i]) !== scoreToZone(scores[i - 1])) zoneJumps++;
    }
    const jumpRate = zoneJumps / (n - 1);

    // 大幅跳跃 (>15分)
    let bigJumps = 0;
    for (let i = 1; i < n; i++) {
      if (Math.abs(scores[i] - scores[i - 1]) > 15) bigJumps++;
    }
    const bigJumpRate = bigJumps / (n - 1);

    // ===== 5. IP切换检测 =====
    let ipSwitches = 0;
    for (let i = 1; i < sessions.length; i++) {
      if (sessions[i].ip && sessions[i - 1].ip && sessions[i].ip !== sessions[i - 1].ip) {
        ipSwitches++;
      }
    }
    // 当前IP的专属历史
    const currentIPHistory = currentIP
      ? sessions.filter(h => h.ip === currentIP)
      : sessions;
    const cipScores = currentIPHistory.map(h => h.score);
    const cipAvg = cipScores.length > 0 ? cipScores.reduce((a, b) => a + b, 0) / cipScores.length : avg;

    // ===== 6. 趋势分析（改进版） =====
    const recentN = Math.min(8, Math.floor(n / 2));
    const olderN = n - recentN;
    const recentAvg = scores.slice(-recentN).reduce((a, b) => a + b, 0) / recentN;
    const olderAvg = scores.slice(0, olderN).reduce((a, b) => a + b, 0) / olderN;
    const trendDelta = recentAvg - olderAvg;
    // EMA交叉信号
    const emaCross = emaShort - emaLong; // >0 恶化信号, <0 改善信号
    let trend;
    if (trendDelta > 5 && emaCross > 3) trend = '📈 双线确认恶化';
    else if (trendDelta > 5) trend = '📈 趋势恶化';
    else if (trendDelta < -5 && emaCross < -3) trend = '📉 双线确认改善';
    else if (trendDelta < -5) trend = '📉 趋势改善';
    else if (Math.abs(emaCross) > 5) trend = emaCross > 0 ? '⚠️ 短期恶化信号' : '✨ 短期改善信号';
    else trend = '➡️ 基本持平';

    // ===== 7. 模式检测 =====
    // 锯齿波：相邻3条记录反复 高→低→高 或 低→高→低（差值>12）
    let sawtoothCount = 0;
    for (let i = 2; i < scores.length; i++) {
      const d1 = scores[i - 1] - scores[i - 2];
      const d2 = scores[i] - scores[i - 1];
      if (d1 * d2 < 0 && Math.abs(d1) > 12 && Math.abs(d2) > 12) {
        sawtoothCount++;
      }
    }
    const sawtoothDetected = sawtoothCount >= 2;

    // 阶梯恶化：连续3次以上每次都比前一次高
    let maxStairUp = 0, curStairUp = 0;
    for (let i = 1; i < scores.length; i++) {
      if (scores[i] > scores[i - 1] + 2) { curStairUp++; maxStairUp = Math.max(maxStairUp, curStairUp); }
      else curStairUp = 0;
    }
    const stairDetected = maxStairUp >= 3;

    // ===== 8. 峰值分析 =====
    const peakScore = Math.max(...scores);
    const recentPeakScore = Math.max(...scores.slice(-8));

    // ===== 9. 稳定性评分 (0-100) =====
    const stability = Math.max(0, Math.min(100, Math.round(
      100
      - volatility * 0.30
      - jumpRate * 100 * 0.20
      - bigJumpRate * 100 * 0.20
      - (sawtoothDetected ? 15 : 0)
      - (stairDetected ? 10 : 0)
      - Math.min(ipSwitches * 3, 15)
    )));

    // ===== 10. 置信度 (0-100) =====
    // 基于：数据量、时间跨度、当前IP数据量
    const timeSpan = times[n - 1] - times[0];
    const daysCovered = timeSpan / DAY_MS;
    const dataConf = Math.min(40, n * 3);       // 最多40分 (≥14条满分)
    const spanConf = Math.min(30, daysCovered * 10); // 最多30分 (≥3天满分)
    const cipConf = Math.min(30, cipScores.length * 5); // 最多30分 (≥6条满分)
    const confidence = Math.round(Math.min(100, dataConf + spanConf + cipConf));

    // ===== 11. 综合风险评分 (0-100) =====
    // 加权合成：时间衰减均值(40%) + 当前分数(25%) + 当前IP均值(20%) + 趋势修正(15%)
    let compositeRisk = weightedAvg * 0.40 + currentScore * 0.25 + cipAvg * 0.20;
    // 趋势修正
    if (trendDelta > 5) compositeRisk += Math.min(trendDelta * 0.8, 10);
    else if (trendDelta < -5) compositeRisk += Math.max(trendDelta * 0.5, -8);
    // 波动惩罚：不稳定的IP额外加分
    if (sawtoothDetected) compositeRisk += 8;
    if (stairDetected) compositeRisk += 5;
    if (bigJumpRate > 0.3) compositeRisk += 5;
    compositeRisk = Math.max(0, Math.min(100, Math.round(compositeRisk)));

    // ===== 12. 算法判定逻辑（基于综合评分） =====
    let verdict, verdictLevel;

    if (currentScore <= 15) {
      if (compositeRisk <= 20 && stability >= 55) {
        verdict = '🟢 IP极其纯净，综合评分' + compositeRisk + '，历史稳定，零降智风险';
        verdictLevel = 'safe';
      } else if (compositeRisk <= 35) {
        verdict = '🟢 当前纯净，综合评分' + compositeRisk + '，历史存在波动但当前状态优秀';
        verdictLevel = 'safe';
      } else {
        verdict = '🟡 当前纯净但综合评分' + compositeRisk + '偏高，历史波动较大或IP频繁切换，持续观察';
        verdictLevel = 'warn';
      }
    } else if (currentScore <= 25) {
      if (compositeRisk <= 25 && stability >= 50) {
        verdict = '🟢 IP质量良好，综合评分' + compositeRisk + '，运行稳定，无降智风险';
        verdictLevel = 'safe';
      } else if (compositeRisk <= 35) {
        verdict = '🟢 IP质量良好，综合评分' + compositeRisk + '，轻微波动属正常范围';
        verdictLevel = 'safe';
      } else if (sawtoothDetected) {
        verdict = '🟡 当前良好但检测到锯齿波动模式（忽高忽低），可能为共享/轮转节点';
        verdictLevel = 'warn';
      } else {
        verdict = '🟡 当前良好但综合评分' + compositeRisk + '偏高，建议持续观察';
        verdictLevel = 'warn';
      }
    } else if (currentScore <= 40) {
      // ★ 灰色地带核心研判 ★
      if (compositeRisk <= 30 && stability >= 60 && cipAvg <= 35) {
        verdict = '🟢 中等偏好区间，但综合评分仅' + compositeRisk + '，当前IP历史稳定均值' + Math.round(cipAvg) + '，暂无降智风险';
        verdictLevel = 'safe';
      } else if (compositeRisk <= 40 && stability >= 45 && !sawtoothDetected) {
        verdict = '🟡 中等偏好区间，综合评分' + compositeRisk + '，相对稳定，存在轻微风险';
        verdictLevel = 'warn';
      } else if (sawtoothDetected) {
        verdict = '🔴 中等偏好区间 + 锯齿波动模式！分数忽高忽低振荡' + sawtoothCount + '次，判定为高降智风险';
        verdictLevel = 'danger';
      } else if (stairDetected) {
        verdict = '🔴 检测到阶梯恶化模式！风控分持续走高（连续' + maxStairUp + '次递增），趋势危险';
        verdictLevel = 'danger';
      } else if (compositeRisk >= 50) {
        verdict = '🔴 综合评分' + compositeRisk + '过高，虽然当前' + currentScore + '但历史数据表明高风险';
        verdictLevel = 'danger';
      } else if (emaCross > 5) {
        verdict = '🟠 EMA短期线高于长期线（+' + Math.round(emaCross) + '），恶化信号明显，有降智风险';
        verdictLevel = 'warn';
      } else {
        verdict = '🟡 中等偏好区间，综合评分' + compositeRisk + '，波动不确定，存在一定降智风险';
        verdictLevel = 'warn';
      }
    } else if (currentScore <= 50) {
      if (sawtoothDetected || stairDetected || compositeRisk >= 55) {
        verdict = '🔴 中等偏下 + 异常波动模式，综合评分' + compositeRisk + '，降智风险很高';
        verdictLevel = 'danger';
      } else {
        verdict = '🟠 中等偏下区间，综合评分' + compositeRisk + '，建议更换节点';
        verdictLevel = 'danger';
      }
    } else if (currentScore <= 60) {
      verdict = '🔴 IP质量差（' + currentScore + '），综合评分' + compositeRisk + '，风险极高，强烈建议更换';
      verdictLevel = 'danger';
    } else if (currentScore <= 70) {
      verdict = '🔴 IP极差（' + currentScore + '），几乎确定已降智，请立即更换节点';
      verdictLevel = 'danger';
    } else {
      verdict = '☠️ 百分百降智！风控分' + currentScore + '，此IP已被标记为极高风险，必须立即更换';
      verdictLevel = 'danger';
    }

    // 附加提示
    if (ipSwitches > 3 && verdictLevel !== 'danger') {
      verdict += '\n⚠️ 检测到频繁切换IP（' + ipSwitches + '次），建议固定优质节点';
    }
    if (confidence < 50) {
      verdict += '\n📊 置信度' + confidence + '%，数据量不足，结论仅供参考';
    }

    return {
      verdict,
      verdictLevel,
      avgScore: Math.round(avg * 10) / 10,
      weightedAvg: Math.round(weightedAvg * 10) / 10,
      stdDev: Math.round(stdDev * 10) / 10,
      volatility,
      zoneJumps,
      trend,
      trendDelta: Math.round(trendDelta * 10) / 10,
      totalRecords: allHistory.length,
      totalSessions: n,
      stability,
      confidence,
      compositeRisk,
      ipSwitches,
      currentIPHistory: cipScores,
      emaShort,
      emaLong,
      sawtoothDetected,
      stairDetected,
      peakScore,
      recentPeakScore,
    };
  }

  // ==================== 样式 ====================
  // v5 override: keep the output schema stable for existing UI rendering.
  function analyzeHistory(currentScore, currentIP, powSnapshot) {
    currentScore = clamp(Number(currentScore) || 0, 0, 100);
    currentIP = typeof currentIP === 'string' ? currentIP.trim() : '';
    const allHistory = normalizeHistoryRecords(loadHistory());
    const now = Date.now();
    const powAnalysis = analyzePowHistory(powSnapshot, now);
    const sessions = buildSessions(allHistory);
    const n = sessions.length;
    const baseCurrentIPHistory = currentIP
      ? sessions.filter(session => session.ip === currentIP)
      : sessions;

    if (n < 3) {
      const baseLevel = currentScore <= 25 ? 'safe' : (currentScore <= 50 ? 'warn' : 'danger');
      return {
        verdict: '📊 数据积累中（' + n + '/3），需更多访问以启动深度分析',
        verdictLevel: baseLevel,
        avgScore: currentScore,
        weightedAvg: currentScore,
        stdDev: 0,
        volatility: 0,
        zoneJumps: 0,
        trend: '—',
        trendDelta: 0,
        totalRecords: allHistory.length,
        totalSessions: n,
        stability: 50,
        confidence: Math.round(n / 3 * 30),
        compositeRisk: currentScore,
        ipSwitches: 0,
        currentIPHistory: baseCurrentIPHistory.map(item => item.score),
        emaShort: currentScore,
        emaLong: currentScore,
        sawtoothDetected: false,
        stairDetected: false,
        peakScore: currentScore,
        recentPeakScore: currentScore,
        recentHighRiskRatio: 0,
        currentHighRiskStreak: currentScore >= 40 ? 1 : 0,
        effectiveSamples: n,
        robustStd: 0,
        powRisk: powAnalysis.powRisk,
        powLowRatio: powAnalysis.powLowRatio,
        powHighRatio: powAnalysis.powHighRatio,
        powTrend: powAnalysis.powTrend,
        powSampleCount: powAnalysis.powSampleCount,
        powCurrentLabel: powAnalysis.powCurrentLabel,
        powCurrentDifficulty: powAnalysis.powCurrentDifficulty,
        powCurrentDigits: powAnalysis.powCurrentDigits,
        powCurrentAgeMinutes: powAnalysis.powCurrentAgeMinutes,
        powCurrentStrength: powAnalysis.powCurrentStrength,
        powAvailable: powAnalysis.powAvailable,
        powFresh: powAnalysis.powFresh,
      };
    }

    const scores = sessions.map(item => item.score);
    const times = sessions.map(item => item.ts);
    const avg = average(scores);
    const variance = average(scores.map(score => (score - avg) ** 2));
    const stdDev = Math.sqrt(variance);
    const mad = calcMAD(scores);
    const robustStd = mad * 1.4826;
    const q75 = calcPercentile(scores, 0.75);

    const HALF_LIFE = DAY_MS;
    const lambda = Math.LN2 / HALF_LIFE;
    let weightedSum = 0;
    let weightTotal = 0;
    let weightSquares = 0;
    for (let i = 0; i < n; i++) {
      const age = now - times[i];
      const weight = Math.exp(-lambda * age);
      weightedSum += scores[i] * weight;
      weightTotal += weight;
      weightSquares += weight * weight;
    }
    const weightedAvg = weightTotal > 0 ? weightedSum / weightTotal : avg;
    const effectiveSamples = weightSquares > 0 ? (weightTotal * weightTotal) / weightSquares : n;

    const emaShortRaw = calcEMA(scores, Math.min(5, n));
    const emaLongRaw = calcEMA(scores, Math.min(15, n));
    const emaShort = round1(emaShortRaw);
    const emaLong = round1(emaLongRaw);

    let zoneJumps = 0;
    let bigJumps = 0;
    for (let i = 1; i < n; i++) {
      if (scoreToZone(scores[i]) !== scoreToZone(scores[i - 1])) zoneJumps++;
      if (Math.abs(scores[i] - scores[i - 1]) > 15) bigJumps++;
    }
    const jumpRate = zoneJumps / Math.max(1, n - 1);
    const bigJumpRate = bigJumps / Math.max(1, n - 1);

    let ipSwitches = 0;
    for (let i = 1; i < sessions.length; i++) {
      if (sessions[i].ip && sessions[i - 1].ip && sessions[i].ip !== sessions[i - 1].ip) {
        ipSwitches++;
      }
    }
    const currentIPHistory = currentIP
      ? sessions.filter(item => item.ip === currentIP)
      : sessions;
    const cipScores = currentIPHistory.map(item => item.score);
    const cipAvg = cipScores.length ? average(cipScores) : avg;
    const cipRecentAvg = cipScores.length ? average(cipScores.slice(-Math.min(4, cipScores.length))) : cipAvg;

    const recentN = Math.min(8, Math.max(2, Math.ceil(n * 0.4)));
    const olderN = Math.max(1, n - recentN);
    const recentWindow = scores.slice(-recentN);
    const olderWindow = scores.slice(0, olderN);
    const recentAvg = average(recentWindow);
    const olderAvg = average(olderWindow);
    const trendDelta = recentAvg - olderAvg;
    const emaCross = emaShortRaw - emaLongRaw;
    const slopeRecent = calcSlope(scores.slice(-Math.min(6, n)));
    const trendSignal = trendDelta * 0.55 + emaCross * 0.9 + slopeRecent * 3.5;

    let trend;
    if (trendSignal >= 10 || (trendDelta > 6 && emaCross > 3 && slopeRecent > 1.5)) trend = '📈 双线确认恶化';
    else if (trendSignal >= 5) trend = '📈 趋势恶化';
    else if (trendSignal <= -10 || (trendDelta < -6 && emaCross < -3 && slopeRecent < -1.5)) trend = '📉 双线确认改善';
    else if (trendSignal <= -5) trend = '📉 趋势改善';
    else if (emaCross > 4 || slopeRecent > 2) trend = '⚠️ 短期恶化信号';
    else if (emaCross < -4 || slopeRecent < -2) trend = '✅ 短期改善信号';
    else trend = '➡️ 基本持平';

    let sawtoothCount = 0;
    for (let i = 2; i < scores.length; i++) {
      const d1 = scores[i - 1] - scores[i - 2];
      const d2 = scores[i] - scores[i - 1];
      if (d1 * d2 < 0 && Math.abs(d1) >= 10 && Math.abs(d2) >= 10) {
        sawtoothCount++;
      }
    }
    const sawtoothDetected = sawtoothCount >= 2;

    let maxStairUp = 0;
    let curStairUp = 0;
    for (let i = 1; i < scores.length; i++) {
      if (scores[i] >= scores[i - 1] + 2) {
        curStairUp++;
        maxStairUp = Math.max(maxStairUp, curStairUp);
      } else {
        curStairUp = 0;
      }
    }
    const stairDetected = maxStairUp >= 3 && trendDelta >= 3;

    let maxHighRiskStreak = 0;
    let curHighRiskStreak = 0;
    for (const score of scores) {
      if (score >= 40) {
        curHighRiskStreak++;
        maxHighRiskStreak = Math.max(maxHighRiskStreak, curHighRiskStreak);
      } else {
        curHighRiskStreak = 0;
      }
    }
    let currentHighRiskStreak = 0;
    for (let i = scores.length - 1; i >= 0; i--) {
      if (scores[i] >= 40) currentHighRiskStreak++;
      else break;
    }
    const recentHighRiskWindow = scores.slice(-Math.min(6, n));
    const recentHighRiskRatio = recentHighRiskWindow.filter(score => score >= 40).length / recentHighRiskWindow.length;

    const sessionPeaks = sessions.map(session => session.sessionPeak || session.score);
    const peakScore = Math.max(...sessionPeaks);
    const recentPeakScore = Math.max(...sessionPeaks.slice(-8));

    const dispersion = stdDev * 0.65 + robustStd * 0.35;
    let volatility = Math.round(clamp(
      (dispersion / 38) * 100
      + jumpRate * 18
      + bigJumpRate * 24
      + recentHighRiskRatio * 10,
      0,
      100
    ));
    if (sawtoothDetected) volatility = clamp(volatility + 8, 0, 100);
    if (stairDetected) volatility = clamp(volatility + 6, 0, 100);

    const stability = Math.round(clamp(
      100
      - volatility * 0.45
      - jumpRate * 100 * 0.18
      - bigJumpRate * 100 * 0.18
      - recentHighRiskRatio * 14
      - (sawtoothDetected ? 10 : 0)
      - (stairDetected ? 10 : 0)
      - Math.min(ipSwitches * 3, 12)
      + (trendSignal < -6 ? 4 : 0),
      0,
      100
    ));

    const timeSpan = times[n - 1] - times[0];
    const daysCovered = timeSpan / DAY_MS;
    const dataConf = Math.min(38, effectiveSamples * 6.5);
    const spanConf = Math.min(24, daysCovered * 8);
    const cipConf = Math.min(22, cipScores.length * 5.5);
    const consistencyConf = clamp(16 - bigJumpRate * 18 - jumpRate * 8 - Math.min(ipSwitches * 1.5, 6), 2, 16);
    let confidence = Math.round(clamp(dataConf + spanConf + cipConf + consistencyConf, 15, 100));
    if (n < 5 && daysCovered < 1) confidence = Math.min(confidence, 58);
    if (currentIP && cipScores.length < 2) confidence = Math.min(confidence, 64);

    let compositeRisk =
      weightedAvg * 0.24
      + currentScore * 0.24
      + cipAvg * 0.15
      + cipRecentAvg * 0.12
      + recentAvg * 0.14
      + q75 * 0.11;
    const trendAdjustment = clamp(trendSignal * 1.25, -8, 12);
    const persistencePenalty = recentHighRiskRatio * 10 + Math.min(currentHighRiskStreak * 2.5, 10);
    const patternPenalty = (sawtoothDetected ? 6 : 0) + (stairDetected ? 8 : 0) + (bigJumpRate > 0.3 ? 4 : 0);
    const peakPenalty = clamp((recentPeakScore - recentAvg) * 0.18, 0, 4);
    const recoveryBonus = trendSignal < -6 && currentScore < weightedAvg && recentHighRiskRatio < 0.34 ? 4 : 0;
    const powImpactWeight = !powAnalysis.powAvailable
      ? 0
      : (powAnalysis.powFresh ? (powAnalysis.powSampleCount >= 3 ? 0.22 : 0.12) : 0.08);
    const powAdjustment = powImpactWeight > 0
      ? clamp((powAnalysis.powRisk - 45) * powImpactWeight, -8, 12)
      : 0;
    const powPatternPenalty = powAnalysis.powAvailable && powAnalysis.powCurrentDigits <= 3 && powAnalysis.powLowRatio >= 50 ? 6 : 0;
    const powRecoveryBonus = powAnalysis.powAvailable && powAnalysis.powCurrentDigits >= 5 && powAnalysis.powHighRatio >= 35 ? 4 : 0;
    compositeRisk = Math.round(clamp(
      compositeRisk + trendAdjustment + persistencePenalty + patternPenalty + peakPenalty + powAdjustment + powPatternPenalty - recoveryBonus - powRecoveryBonus,
      0,
      100
    ));

    if (powAnalysis.powAvailable) {
      const ipLooksRisky = currentScore >= 40 || compositeRisk >= 45 || recentHighRiskRatio >= 0.5;
      const ipLooksClean = currentScore <= 25 && compositeRisk <= 32 && recentHighRiskRatio <= 0.2;
      const powLooksRisky = powAnalysis.powRisk >= 65 || (powAnalysis.powCurrentDigits <= 3 && powAnalysis.powLowRatio >= 50);
      const powLooksClean = powAnalysis.powRisk <= 30 && powAnalysis.powCurrentDigits >= 5;
      if ((ipLooksRisky && powLooksRisky) || (ipLooksClean && powLooksClean)) {
        confidence = Math.round(clamp(confidence + Math.min(6, 2 + powAnalysis.powSampleCount), 15, 100));
      } else if ((ipLooksRisky && powLooksClean) || (ipLooksClean && powLooksRisky)) {
        confidence = Math.round(clamp(confidence - Math.min(8, 3 + powAnalysis.powSampleCount), 15, 100));
      }
    }

    let verdict, verdictLevel;
    const severePattern = sawtoothDetected || stairDetected || currentHighRiskStreak >= 3 || maxHighRiskStreak >= 4;
    const powSevere = powAnalysis.powAvailable && (powAnalysis.powRisk >= 68 || (powAnalysis.powCurrentDigits <= 3 && powAnalysis.powLowRatio >= 50));
    const powPositive = powAnalysis.powAvailable && powAnalysis.powRisk <= 30 && powAnalysis.powCurrentDigits >= 5 && powAnalysis.powHighRatio >= 30;

    if (currentScore <= 15) {
      if (compositeRisk <= 18 && stability >= 70 && trendSignal <= 1 && recentHighRiskRatio === 0 && !powSevere) {
        verdict = '🟢 IP极其纯净，综合评分' + compositeRisk + '，历史稳定，零降智风险';
        verdictLevel = 'safe';
      } else if (compositeRisk <= 32 && currentHighRiskStreak === 0 && !powSevere) {
        verdict = '🟢 当前纯净，综合评分' + compositeRisk + '，历史存在波动但当前状态优秀';
        verdictLevel = 'safe';
      } else {
        verdict = '🟡 当前纯净但综合评分' + compositeRisk + '偏高，历史波动较大或IP频繁切换，持续观察';
        verdictLevel = 'warn';
      }
    } else if (currentScore <= 25) {
      if (compositeRisk <= 25 && stability >= 55 && recentHighRiskRatio <= 0.2 && !powSevere) {
        verdict = '🟢 IP质量良好，综合评分' + compositeRisk + '，运行稳定，无降智风险';
        verdictLevel = 'safe';
      } else if (compositeRisk <= 35 && !severePattern && !powSevere) {
        verdict = '🟢 IP质量良好，综合评分' + compositeRisk + '，轻微波动属正常范围';
        verdictLevel = 'safe';
      } else if (sawtoothDetected || recentHighRiskRatio >= 0.5) {
        verdict = '🟡 当前良好但检测到锯齿波动模式（忽高忽低），可能为共享/轮转节点';
        verdictLevel = 'warn';
      } else {
        verdict = '🟡 当前良好但综合评分' + compositeRisk + '偏高，建议持续观察';
        verdictLevel = 'warn';
      }
    } else if (currentScore <= 40) {
      if (compositeRisk <= 30 && stability >= 65 && cipAvg <= 35 && recentHighRiskRatio <= 0.25 && !powSevere) {
        verdict = '🟢 中等偏好区间，但综合评分仅' + compositeRisk + '，当前IP历史稳定均值' + Math.round(cipAvg) + '，暂无降智风险';
        verdictLevel = 'safe';
      } else if (compositeRisk <= 40 && stability >= 45 && !severePattern && trendSignal < 6) {
        verdict = '🟡 中等偏好区间，综合评分' + compositeRisk + '，相对稳定，存在轻微风险';
        verdictLevel = 'warn';
      } else if (sawtoothDetected) {
        verdict = '🔴 中等偏好区间 + 锯齿波动模式！分数忽高忽低振荡' + sawtoothCount + '次，判定为高降智风险';
        verdictLevel = 'danger';
      } else if (stairDetected) {
        verdict = '🔴 检测到阶梯恶化模式！风控分持续走高（连续' + maxStairUp + '次递增），趋势危险';
        verdictLevel = 'danger';
      } else if (currentHighRiskStreak >= 2 || recentHighRiskRatio >= 0.5 || compositeRisk >= 50) {
        verdict = '🔴 综合评分' + compositeRisk + '过高，虽然当前' + currentScore + '但历史数据表明高风险';
        verdictLevel = 'danger';
      } else if (emaCross > 5 || slopeRecent > 2) {
        verdict = '🟠 EMA短期线高于长期线（+' + Math.round(emaCross) + '），恶化信号明显，有降智风险';
        verdictLevel = 'warn';
      } else {
        verdict = '🟡 中等偏好区间，综合评分' + compositeRisk + '，波动不确定，存在一定降智风险';
        verdictLevel = 'warn';
      }
    } else if (currentScore <= 50) {
      if (severePattern || compositeRisk >= 55 || recentHighRiskRatio >= 0.5) {
        verdict = '🔴 中等偏下 + 异常波动模式，综合评分' + compositeRisk + '，降智风险很高';
        verdictLevel = 'danger';
      } else {
        verdict = '🟠 中等偏下区间，综合评分' + compositeRisk + '，建议更换节点';
        verdictLevel = 'danger';
      }
    } else if (currentScore <= 60) {
      verdict = '🔴 IP质量差（' + currentScore + '），综合评分' + compositeRisk + '，风险极高，强烈建议更换';
      verdictLevel = 'danger';
    } else if (currentScore <= 70) {
      verdict = '🔴 IP极差（' + currentScore + '），几乎确定已降智，请立即更换节点';
      verdictLevel = 'danger';
    } else {
      verdict = '☠️ 百分百降智！风控分' + currentScore + '，此IP已被标记为极高风险，必须立即更换';
      verdictLevel = 'danger';
    }

    if (ipSwitches > 3 && verdictLevel !== 'danger') {
      verdict += '\n⚠️ 检测到频繁切换IP（' + ipSwitches + '次），建议固定优质节点';
    }
    if (currentHighRiskStreak >= 2) {
      verdict += '\n🔥 当前已连续' + currentHighRiskStreak + '个会话处于高风险区，建议尽快更换节点';
    }
    if (powSevere) {
      verdict += '\n⚡ PoW difficulty stays low (current ' + powAnalysis.powCurrentLabel + ' / ' + powAnalysis.powCurrentDigits + ' digits, low-difficulty ratio ' + powAnalysis.powLowRatio + '%), suggesting weaker conversation entry quality.';
      if (verdictLevel === 'safe') verdictLevel = 'warn';
      else if (verdictLevel === 'warn' && currentScore >= 26 && compositeRisk >= 45) verdictLevel = 'danger';
    } else if (powPositive) {
      verdict += '\n⚡ PoW difficulty stays high (current ' + powAnalysis.powCurrentLabel + ' / ' + powAnalysis.powCurrentDigits + ' digits), consistent with a lower degradation risk.';
    }
    if (confidence < 50) {
      verdict += '\n📊 置信度' + confidence + '%，数据量不足，结论仅供参考';
    } else if (confidence < 65 && verdictLevel === 'safe') {
      verdict += '\n📊 当前结论偏保守，建议继续积累几个会话后再看是否稳定';
    }

    return {
      verdict,
      verdictLevel,
      avgScore: round1(avg),
      weightedAvg: round1(weightedAvg),
      stdDev: round1(stdDev),
      volatility,
      zoneJumps,
      trend,
      trendDelta: round1(trendDelta),
      totalRecords: allHistory.length,
      totalSessions: n,
      stability,
      confidence,
      compositeRisk,
      ipSwitches,
      currentIPHistory: cipScores,
      emaShort,
      emaLong,
      sawtoothDetected,
      stairDetected,
      peakScore,
      recentPeakScore,
      recentHighRiskRatio: round1(recentHighRiskRatio * 100),
      currentHighRiskStreak,
      effectiveSamples: round1(effectiveSamples),
      robustStd: round1(robustStd),
      powRisk: powAnalysis.powRisk,
      powLowRatio: powAnalysis.powLowRatio,
      powHighRatio: powAnalysis.powHighRatio,
      powTrend: powAnalysis.powTrend,
      powSampleCount: powAnalysis.powSampleCount,
      powCurrentLabel: powAnalysis.powCurrentLabel,
      powCurrentDifficulty: powAnalysis.powCurrentDifficulty,
      powCurrentDigits: powAnalysis.powCurrentDigits,
      powCurrentAgeMinutes: powAnalysis.powCurrentAgeMinutes,
      powCurrentStrength: powAnalysis.powCurrentStrength,
      powAvailable: powAnalysis.powAvailable,
      powFresh: powAnalysis.powFresh,
    };
  }

  const css = `
    /* ===== 侧边栏按钮 ===== */
    #ip-sidebar-toggle {
      position: fixed;
      top: 50%;
      right: 0;
      transform: translateY(-50%);
      z-index: 2147483647;
      width: 36px;
      height: 100px;
      background: rgba(20, 20, 20, 0.75);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      color: #fff;
      border: 1px solid rgba(255, 255, 255, 0.12);
      border-right: none;
      border-radius: 14px 0 0 14px;
      cursor: pointer;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      font-size: 13px;
      font-weight: 600;
      letter-spacing: 2px;
      user-select: none;
      box-shadow: -4px 0 20px rgba(0, 0, 0, 0.3);
      transition: all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1);
    }
    #ip-sidebar-toggle:hover {
      background: rgba(40, 40, 40, 0.9);
      box-shadow: -6px 0 28px rgba(0, 0, 0, 0.4);
    }
    .toggle-icon { font-size: 18px; margin-bottom: 6px; }
    .toggle-text { writing-mode: vertical-rl; font-size: 12px; }

    /* ===== 迷你弹出卡片 ===== */
    #ip-mini-card {
      position: fixed;
      top: 50%;
      right: 46px;
      transform: translateY(-50%) scale(0.9);
      z-index: 2147483646;
      width: min(320px, calc(100vw - 64px));
      max-height: calc(100vh - 32px);
      background: rgba(18, 18, 22, 0.92);
      backdrop-filter: blur(24px) saturate(1.2);
      -webkit-backdrop-filter: blur(24px) saturate(1.2);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 16px;
      box-shadow: 0 12px 48px rgba(0, 0, 0, 0.5);
      color: #fff;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Noto Sans SC", sans-serif;
      opacity: 0;
      pointer-events: none;
      transition: all 0.25s cubic-bezier(0.25, 0.8, 0.25, 1);
      overflow: hidden;
    }
    #ip-mini-card.detail-open {
      width: min(380px, calc(100vw - 64px));
    }
    #ip-mini-card.open {
      opacity: 1;
      pointer-events: auto;
      transform: translateY(-50%) scale(1);
    }
    .mini-body {
      padding: 20px;
      max-height: calc(100vh - 32px);
      overflow-y: auto;
      overscroll-behavior: contain;
    }
    .mini-body::-webkit-scrollbar { width: 6px; }
    .mini-body::-webkit-scrollbar-thumb {
      background: rgba(255,255,255,0.12);
      border-radius: 999px;
    }
    .mini-body::-webkit-scrollbar-thumb:hover {
      background: rgba(255,255,255,0.2);
    }
    .mini-loading {
      display: flex;
      flex-direction: column;
      align-items: center;
      padding: 24px 0;
      color: rgba(255,255,255,0.7);
      font-size: 13px;
    }
    .mini-detail-shell {
      margin-top: 12px;
      padding-top: 14px;
      border-top: 1px solid rgba(255,255,255,0.08);
    }
    .mini-detail-shell .algo-verdict,
    .mini-detail-shell .risk-ruler,
    .mini-detail-shell .sparkline-box,
    .mini-detail-shell .info-item,
    .mini-detail-shell .algo-metric {
      box-shadow: none;
    }
    .mini-detail-shell .risk-ruler,
    .mini-detail-shell .sparkline-box,
    .mini-detail-shell .info-item,
    .mini-detail-shell .algo-metric {
      margin-bottom: 12px;
    }
    .mini-detail-shell .algo-grid {
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
      margin-bottom: 12px;
    }
    .mini-detail-shell .algo-metric {
      padding: 12px 10px;
      border-radius: 12px;
    }
    .mini-detail-shell .algo-metric-value {
      font-size: 20px;
    }
    .mini-detail-shell .algo-metric-value.compact {
      font-size: 16px;
    }
    .mini-detail-shell .info-grid {
      gap: 10px;
      margin-bottom: 12px;
    }
    .mini-detail-shell .info-item {
      padding: 14px 16px;
      border-radius: 12px;
    }
    .mini-detail-shell .info-item-value {
      flex-direction: column;
      align-items: flex-start;
      justify-content: flex-start;
      gap: 6px;
    }
    .mini-detail-shell .sparkline-box {
      padding: 16px;
    }
    .mini-detail-shell .sparkline-title,
    .mini-detail-shell .ruler-title,
    .mini-detail-shell .info-item-header,
    .mini-detail-shell .algo-title {
      letter-spacing: 1px;
    }
    .mini-detail-shell .ruler-labels {
      font-size: 9px;
    }
    .mini-record-count {
      color: rgba(255,255,255,0.45);
      margin-top: 2px;
    }

    /* ===== 禅意极简 全屏详情页面 ===== */
    #ip-fullscreen-overlay {
      position: fixed;
      inset: 0;
      z-index: 2147483647;
      background: #F8F6F1; /* 纯净米白底色 */
      display: flex;
      align-items: flex-start;
      justify-content: center;
      opacity: 0;
      pointer-events: none;
      transition: opacity 0.5s ease;
    }
    #ip-fullscreen-overlay.open {
      opacity: 1;
      pointer-events: auto;
    }
    #ip-fullscreen-panel {
      width: 100vw;
      height: 100vh;
      max-width: none;
      max-height: none;
      background: linear-gradient(135deg, rgba(248, 246, 241, 0.98) 0%, rgba(240, 238, 230, 0.95) 100%);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border: none;
      border-radius: 0;
      box-shadow: none;
      color: #2D3142; /* 深邃炭灰 */
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Noto Sans SC", sans-serif;
      overflow-y: auto;
      transform: translateY(20px);
      opacity: 0;
      transition: transform 0.6s cubic-bezier(0.2, 0.8, 0.2, 1), opacity 0.6s ease;
      display: flex;
      flex-direction: column;
    }
    #ip-fullscreen-overlay.open #ip-fullscreen-panel {
      transform: translateY(0);
      opacity: 1;
    }
    #ip-fullscreen-panel::-webkit-scrollbar { width: 8px; }
    #ip-fullscreen-panel::-webkit-scrollbar-thumb { background: rgba(45, 49, 66, 0.15); border-radius: 10px; }
    #ip-fullscreen-panel::-webkit-scrollbar-thumb:hover { background: rgba(45, 49, 66, 0.25); }

    .full-header {
      padding: 24px 5vw;
      background: rgba(248, 246, 241, 0.85); /* 半透明 */
      backdrop-filter: blur(12px);
      border-bottom: 1px solid rgba(45, 49, 66, 0.05);
      position: sticky;
      top: 0;
      z-index: 10;
    }
    .full-header-inner {
      width: 100%;
      max-width: 1080px;
      margin: 0 auto;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .full-header-left { display: flex; align-items: baseline; gap: 12px; }
    .full-header-left .h-icon { font-size: 24px; filter: drop-shadow(0 2px 4px rgba(136,209,138,0.4)); /* 抹茶绿阴影 */ }
    .full-header-left .h-title { font-size: 20px; font-weight: 600; letter-spacing: 1px; color: #2D3142; }
    .full-header-left .h-ver { font-size: 12px; color: rgba(45, 49, 66, 0.4); letter-spacing: 0.5px; }
    .full-close-btn {
      width: 40px; height: 40px;
      border-radius: 12px;
      background: rgba(45, 49, 66, 0.04);
      border: 1px solid transparent;
      color: #2D3142;
      font-size: 20px;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1);
    }
    .full-close-btn:hover { 
      background: rgba(45, 49, 66, 0.08); 
      transform: scale(1.05) rotate(90deg);
    }
    .full-body { 
      padding: 40px 20px 80px; 
      font-size: 14px; 
      color: #2D3142;
      width: 100%;
      max-width: 1080px;
      margin: 0 auto;
      flex: 1;
    }

    /* ===== 共享UI组件 ===== */
    .risk-circle {
      display: flex;
      flex-direction: column;
      align-items: center;
      position: relative;
    }
    .circle-outer {
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      position: relative;
      box-shadow: 0 10px 30px rgba(0,0,0,0.15); /* 禅意柔和阴影 */
      transition: transform 0.5s ease;
    }
    .circle-outer:hover {
      transform: scale(1.02);
    }
    .circle-ring {
      position: absolute;
      inset: 0;
      border-radius: 50%;
      border: 5px solid transparent;
      animation: pulse-ring 3s cubic-bezier(0.4, 0, 0.6, 1) infinite; /* 缓慢呼吸灯 */
    }
    @keyframes pulse-ring {
      0%, 100% { opacity: 0.4; transform: scale(1); }
      50% { opacity: 0.8; transform: scale(1.06); }
    }
    .circle-inner {
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 800;
      z-index: 1;
      backdrop-filter: blur(4px);
    }
    .mini-body .circle-inner { background: rgba(0,0,0,0.5); }
    .full-body .circle-inner { background: rgba(255,255,255,0.85); box-shadow: inset 0 2px 10px rgba(0,0,0,0.05); }

    .risk-label { font-weight: 600; letter-spacing: 2px; }
    .risk-sublabel { font-size: 12px; color: rgba(45,49,66,0.5); margin-top: 4px; letter-spacing: 0.5px; }
    .risk-hero {
      position: relative;
      display: grid;
      align-items: center;
      gap: 20px;
      margin-bottom: 18px;
      overflow: hidden;
    }
    .risk-hero::before {
      content: '';
      position: absolute;
      inset: auto -40px -50px auto;
      width: 150px;
      height: 150px;
      border-radius: 999px;
      background: radial-gradient(circle, rgba(136,209,138,0.18), transparent 68%);
      pointer-events: none;
    }
    .risk-hero-main {
      position: relative;
      z-index: 1;
      min-width: 0;
    }
    .risk-kicker {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 6px 10px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 1px;
      text-transform: uppercase;
      margin-bottom: 12px;
    }
    .risk-hero-top {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 12px;
      flex-wrap: wrap;
    }
    .risk-hero-title {
      font-size: 30px;
      line-height: 1.05;
      font-weight: 800;
      letter-spacing: -0.8px;
      color: #2D3142;
    }
    .risk-hero-subtitle {
      margin-top: 8px;
      font-size: 14px;
      line-height: 1.6;
      color: rgba(45,49,66,0.68);
    }
    .risk-tag-row {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }
    .risk-tag {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 8px 12px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.2px;
      border: 1px solid transparent;
      white-space: nowrap;
    }
    .risk-hero-note {
      margin-top: 14px;
      padding: 14px 16px;
      border-radius: 16px;
      font-size: 13px;
      line-height: 1.65;
      background: rgba(255,255,255,0.62);
      border: 1px solid rgba(45,49,66,0.08);
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.35);
    }
    .risk-chip-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
      gap: 12px;
      margin-top: 16px;
    }
    .risk-chip {
      position: relative;
      overflow: hidden;
      padding: 14px 14px 13px;
      border-radius: 16px;
      background: rgba(255,255,255,0.82);
      border: 1px solid rgba(45,49,66,0.08);
      box-shadow: 0 10px 24px rgba(45,49,66,0.05);
    }
    .risk-chip::after {
      content: '';
      position: absolute;
      inset: auto -18px -22px auto;
      width: 70px;
      height: 70px;
      border-radius: 999px;
      background: radial-gradient(circle, rgba(45,49,66,0.05), transparent 68%);
      pointer-events: none;
    }
    .risk-chip-label {
      display: block;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: rgba(45,49,66,0.46);
      margin-bottom: 8px;
    }
    .risk-chip-value {
      display: block;
      font-size: 24px;
      line-height: 1;
      font-weight: 800;
      letter-spacing: -0.6px;
      color: #2D3142;
      margin-bottom: 6px;
    }
    .risk-chip-hint {
      display: block;
      font-size: 12px;
      color: rgba(45,49,66,0.56);
      line-height: 1.45;
    }
    .risk-hero .risk-circle { margin: 0; }
    .risk-hero .circle-outer { margin-bottom: 0; }

    /* 迷你卡片内的圆环较小 (保持深色主题适配) */
    .mini-body .risk-circle { margin-bottom: 14px; }
    .mini-body .circle-outer { width: 80px; height: 80px; margin-bottom: 8px; box-shadow: 0 0 30px rgba(0,0,0,0.4); }
    .mini-body .circle-ring { border-width: 4px; }
    .mini-body .circle-inner { width: 64px; height: 64px; font-size: 26px; }
    .mini-body .risk-label { font-size: 14px; }
    .mini-body .risk-sublabel { color: rgba(255,255,255,0.5); }
    .mini-body .risk-hero {
      grid-template-columns: 84px minmax(0, 1fr);
      padding: 14px;
      border-radius: 18px;
      background: linear-gradient(135deg, rgba(255,255,255,0.1), rgba(255,255,255,0.04));
      border: 1px solid rgba(255,255,255,0.08);
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.06), 0 18px 40px rgba(0,0,0,0.2);
    }
    .mini-body .risk-kicker {
      background: rgba(255,255,255,0.08);
      color: rgba(255,255,255,0.72);
      margin-bottom: 10px;
    }
    .mini-body .risk-hero-title {
      font-size: 20px;
      color: #fff;
      letter-spacing: -0.4px;
    }
    .mini-body .risk-hero-subtitle {
      font-size: 12px;
      color: rgba(255,255,255,0.56);
      margin-top: 6px;
    }
    .mini-body .risk-hero-note {
      margin-top: 12px;
      padding: 10px 12px;
      font-size: 12px;
      background: rgba(0,0,0,0.18);
      border-color: rgba(255,255,255,0.08);
      color: rgba(255,255,255,0.82);
    }
    .mini-body .risk-tag {
      background: rgba(255,255,255,0.08);
      border-color: rgba(255,255,255,0.08);
      color: rgba(255,255,255,0.76);
      padding: 6px 10px;
      font-size: 11px;
    }
    .mini-body .risk-chip-grid {
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
      margin-top: 12px;
    }
    .mini-body .risk-chip {
      background: rgba(255,255,255,0.06);
      border-color: rgba(255,255,255,0.08);
      box-shadow: none;
      padding: 11px 11px 10px;
    }
    .mini-body .risk-chip-label {
      color: rgba(255,255,255,0.46);
      margin-bottom: 6px;
    }
    .mini-body .risk-chip-value {
      font-size: 18px;
      color: #fff;
      margin-bottom: 4px;
    }
    .mini-body .risk-chip-hint {
      font-size: 11px;
      color: rgba(255,255,255,0.5);
    }

    /* 全屏面板内的圆环较大 (极简主题) */
    .full-body .risk-circle { margin-bottom: 40px; margin-top: 10px; }
    .full-body .circle-outer { width: 140px; height: 140px; margin-bottom: 20px; }
    .full-body .circle-ring { border-width: 8px; }
    .full-body .circle-inner { width: 112px; height: 112px; font-size: 48px; }
    .full-body .risk-label { font-size: 18px; }
    .full-body .risk-hero {
      grid-template-columns: 180px minmax(0, 1fr);
      padding: 26px;
      border-radius: 28px;
      background:
        radial-gradient(circle at top left, rgba(136,209,138,0.18), transparent 28%),
        radial-gradient(circle at top right, rgba(243,156,18,0.12), transparent 30%),
        rgba(255,255,255,0.78);
      border: 1px solid rgba(45,49,66,0.08);
      box-shadow: 0 24px 56px rgba(45,49,66,0.08);
      margin: 8px 0 24px;
    }
    .full-body .risk-kicker {
      background: rgba(45,49,66,0.06);
      color: rgba(45,49,66,0.58);
    }
    .full-body .risk-hero-title {
      font-size: 34px;
    }
    .full-body .risk-chip-value {
      font-size: 28px;
    }
    .full-body .risk-chip-grid {
      grid-template-columns: repeat(4, minmax(0, 1fr));
    }

    .algo-verdict {
      padding: 16px 20px;
      border-radius: 16px;
      margin-bottom: 24px;
      font-size: 13px;
      line-height: 1.7;
      border: 1px solid transparent;
      box-shadow: 0 4px 15px rgba(0,0,0,0.03);
      transition: all 0.3s ease;
      background: #fff;
    }
    .algo-verdict:hover { box-shadow: 0 8px 25px rgba(0,0,0,0.06); transform: translateY(-2px); }
    .mini-body .algo-verdict { background: transparent; box-shadow: none; border: 1px solid; border-radius: 12px; margin-bottom: 14px; padding: 12px 14px; }
    
    .mini-body .algo-verdict.safe { background: rgba(16,185,129,0.1); border-color: rgba(16,185,129,0.3); color: #6ee7b7; }
    .mini-body .algo-verdict.warn { background: rgba(251,191,36,0.1); border-color: rgba(251,191,36,0.3); color: #fde68a; }
    .mini-body .algo-verdict.danger { background: rgba(239,68,68,0.1); border-color: rgba(239,68,68,0.3); color: #fca5a5; }

    .full-body .algo-verdict.safe { border-color: rgba(136, 209, 138, 0.3); border-left: 4px solid #88D18A; } /* 抹茶绿 */
    .full-body .algo-verdict.warn { border-color: rgba(251, 191, 36, 0.3); border-left: 4px solid #FBBF24; }
    .full-body .algo-verdict.danger { border-color: rgba(255, 183, 197, 0.6); border-left: 4px solid #FFB7C5; } /* 樱花粉偏警示 */

    .algo-title { font-size: 12px; text-transform: uppercase; letter-spacing: 1.5px; margin-bottom: 8px; opacity: 0.6; font-weight: 600; }

    .btn-more {
      width: 100%;
      padding: 10px;
      background: rgba(255,255,255,0.1);
      border: 1px solid rgba(255,255,255,0.15);
      color: #fff;
      border-radius: 10px;
      cursor: pointer;
      font-size: 13px;
      font-weight: 600;
      transition: all 0.2s;
      margin-top: 4px;
    }
    .btn-more:hover { background: rgba(255,255,255,0.2); }

    .mini-ip-line {
      text-align: center;
      font-size: 11px;
      color: rgba(255,255,255,0.4);
      margin-top: 8px;
    }

    .sparkline-box {
      background: #fff;
      border-radius: 16px;
      padding: 20px;
      margin-bottom: 24px;
      border: 1px solid rgba(45, 49, 66, 0.05);
      box-shadow: 0 4px 15px rgba(0,0,0,0.02);
      transition: all 0.4s ease;
    }
    .sparkline-box:hover { box-shadow: 0 10px 30px rgba(0,0,0,0.05); }
    .sparkline-title {
      font-size: 11px;
      color: rgba(45, 49, 66, 0.5);
      text-transform: uppercase;
      letter-spacing: 1px;
      margin-bottom: 14px;
      font-weight: 600;
    }
    .sparkline-canvas { width: 100%; height: 70px; display: block; }

    .algo-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
      perspective: 1000px;
    }
    .algo-metric {
      background: #fff;
      padding: 16px;
      border-radius: 16px;
      border: 1px solid rgba(45, 49, 66, 0.05);
      text-align: center;
      box-shadow: 0 4px 15px rgba(0,0,0,0.02);
      transition: transform 0.4s cubic-bezier(0.25, 0.8, 0.25, 1), box-shadow 0.4s ease;
      transform-style: preserve-3d;
    }
    .algo-metric:hover { 
      transform: translateY(-4px) rotateX(2deg);
      box-shadow: 0 12px 24px rgba(45, 49, 66, 0.08); 
    }
    .algo-metric-value { font-size: 24px; font-weight: 700; margin-bottom: 6px; font-family: ui-rounded, sans-serif; letter-spacing: -0.5px; }
    .algo-metric-label { font-size: 11px; color: rgba(45, 49, 66, 0.45); text-transform: uppercase; letter-spacing: 1px; }

    .risk-ruler {
      background: #fff;
      border-radius: 16px;
      padding: 20px;
      margin-bottom: 24px;
      border: 1px solid rgba(45, 49, 66, 0.05);
      box-shadow: 0 4px 15px rgba(0,0,0,0.02);
    }
    .ruler-title { font-size: 11px; color: rgba(45, 49, 66, 0.5); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 14px; font-weight: 600; }
    .ruler-bar {
      height: 6px; /* 更纤细的标尺 */
      border-radius: 3px;
      background: linear-gradient(to right, #88D18A 0%, #A3E4D7 15%, #FDE047 30%, #F5B041 50%, #FFB7C5 65%, #E74C3C 100%);
      position: relative;
      margin-bottom: 8px;
    }
    .ruler-marker {
      position: absolute;
      top: -6px;
      width: 18px; height: 18px;
      border-radius: 50%;
      background: #fff;
      border: 3px solid;
      transform: translateX(-50%);
      box-shadow: 0 2px 8px rgba(45, 49, 66, 0.2);
      transition: left 0.8s cubic-bezier(0.2, 0.8, 0.2, 1);
    }
    .ruler-labels { display: flex; justify-content: space-between; font-size: 10px; color: rgba(45, 49, 66, 0.4); margin-top: 6px; }

    .info-grid { display: grid; grid-template-columns: 1fr; gap: 12px; margin-bottom: 24px; }
    .info-item { 
      background: #fff; 
      padding: 16px 20px; 
      border-radius: 14px; 
      border: 1px solid rgba(45, 49, 66, 0.04);
      box-shadow: 0 2px 10px rgba(0,0,0,0.015);
      transition: background 0.3s;
    }
    .info-item:hover { background: rgba(255,255,255,0.5); }
    .info-item-header { font-size: 11px; color: rgba(45, 49, 66, 0.5); margin-bottom: 8px; text-transform: uppercase; letter-spacing: 1px; font-weight: 600; }
    .info-item-value { font-size: 14px; color: rgba(45, 49, 66, 0.9); word-break: break-all; display: flex; align-items: center; justify-content: space-between; }
    .badge { padding: 4px 10px; border-radius: 8px; font-size: 12px; font-weight: 600; letter-spacing: 0.5px; }

    .btn-row { display: flex; gap: 12px; margin-top: 10px; }
    .btn-refresh, .btn-clear {
      flex: 1; padding: 14px;
      border: none;
      border-radius: 12px;
      cursor: pointer; font-size: 14px; font-weight: 600; letter-spacing: 1px;
      transition: all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1);
      box-shadow: 0 4px 12px rgba(0,0,0,0.05);
    }
    .btn-refresh { background: #2D3142; color: #F8F6F1; }
    .btn-refresh:hover { background: #3d4359; transform: translateY(-2px); box-shadow: 0 6px 16px rgba(45, 49, 66, 0.15); }
    .btn-refresh:active { transform: translateY(0); }
    
    .btn-clear { background: #fff; color: #E74C3C; border: 1px solid rgba(231, 76, 60, 0.2); }
    .btn-clear:hover { background: #fff5f5; border-color: rgba(231, 76, 60, 0.4); transform: translateY(-2px); }

    .loading-state { display: flex; flex-direction: column; align-items: center; padding: 40px 0; color: rgba(255,255,255,0.8); }
    .spinner { width: 32px; height: 32px; border: 3px solid rgba(136, 209, 138, 0.2); border-top-color: #88D18A; border-radius: 50%; animation: spin 1s cubic-bezier(0.6, 0.2, 0.4, 0.8) infinite; margin-bottom: 12px; }
    @keyframes spin { 100% { transform: rotate(360deg); } }
    .record-count { text-align: center; font-size: 11px; color: rgba(45, 49, 66, 0.4); margin-top: 20px; letter-spacing: 0.5px; }

    .detail-dashboard {
      display: flex;
      flex-direction: column;
      gap: 20px;
    }
    .detail-grid-shell {
      display: grid;
      grid-template-columns: minmax(0, 1.35fr) minmax(320px, 0.95fr);
      gap: 18px;
      align-items: start;
    }
    .detail-section {
      position: relative;
      overflow: hidden;
      padding: 22px;
      border-radius: 24px;
      background: rgba(255,255,255,0.76);
      border: 1px solid rgba(45,49,66,0.08);
      box-shadow: 0 20px 44px rgba(45,49,66,0.06);
    }
    .detail-section::before {
      content: '';
      position: absolute;
      top: -48px;
      right: -42px;
      width: 150px;
      height: 150px;
      border-radius: 999px;
      background: radial-gradient(circle, rgba(136,209,138,0.12), transparent 72%);
      pointer-events: none;
    }
    .detail-section-head {
      position: relative;
      z-index: 1;
      display: flex;
      align-items: flex-end;
      justify-content: space-between;
      gap: 14px;
      flex-wrap: wrap;
      margin-bottom: 18px;
    }
    .detail-section-kicker {
      display: inline-block;
      margin-bottom: 8px;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 1.1px;
      text-transform: uppercase;
      color: rgba(45,49,66,0.44);
    }
    .detail-section-title {
      font-size: 22px;
      line-height: 1.1;
      font-weight: 800;
      letter-spacing: -0.6px;
      color: #2D3142;
    }
    .detail-section-note {
      max-width: 420px;
      font-size: 13px;
      line-height: 1.65;
      color: rgba(45,49,66,0.6);
    }
    .detail-meter-grid {
      position: relative;
      z-index: 1;
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 14px;
      margin-bottom: 14px;
    }
    .detail-meter-card {
      padding: 18px;
      border-radius: 18px;
      background: linear-gradient(180deg, rgba(248,246,241,0.98), rgba(255,255,255,0.82));
      border: 1px solid rgba(45,49,66,0.07);
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.6);
    }
    .detail-meter-top {
      display: flex;
      align-items: flex-end;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 14px;
    }
    .detail-meter-label {
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.8px;
      text-transform: uppercase;
      color: rgba(45,49,66,0.48);
    }
    .detail-meter-value {
      font-size: 34px;
      line-height: 1;
      font-weight: 800;
      letter-spacing: -1px;
      color: #2D3142;
    }
    .detail-meter-sub {
      font-size: 12px;
      line-height: 1.55;
      color: rgba(45,49,66,0.58);
      margin-bottom: 12px;
    }
    .detail-meter-track {
      height: 10px;
      border-radius: 999px;
      background: rgba(45,49,66,0.08);
      overflow: hidden;
    }
    .detail-meter-fill {
      height: 100%;
      border-radius: inherit;
      transition: width 0.6s cubic-bezier(0.2, 0.8, 0.2, 1);
    }
    .detail-meter-scale {
      display: flex;
      justify-content: space-between;
      margin-top: 8px;
      font-size: 11px;
      color: rgba(45,49,66,0.42);
    }
    .detail-bar-list {
      position: relative;
      z-index: 1;
      display: grid;
      gap: 12px;
    }
    .detail-bar-row {
      padding: 14px 16px;
      border-radius: 16px;
      background: rgba(248,246,241,0.76);
      border: 1px solid rgba(45,49,66,0.06);
    }
    .detail-bar-meta {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 10px;
    }
    .detail-bar-label {
      font-size: 13px;
      font-weight: 700;
      color: #2D3142;
    }
    .detail-bar-value {
      font-size: 20px;
      line-height: 1;
      font-weight: 800;
      letter-spacing: -0.4px;
    }
    .detail-bar-track {
      height: 8px;
      border-radius: 999px;
      background: rgba(45,49,66,0.08);
      overflow: hidden;
    }
    .detail-bar-fill {
      height: 100%;
      border-radius: inherit;
      transition: width 0.6s cubic-bezier(0.2, 0.8, 0.2, 1);
    }
    .detail-bar-note {
      margin-top: 8px;
      font-size: 12px;
      line-height: 1.5;
      color: rgba(45,49,66,0.54);
    }
    .detail-section .algo-verdict {
      position: relative;
      z-index: 1;
      margin-bottom: 16px;
    }
    .detail-stat-grid {
      position: relative;
      z-index: 1;
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
    }
    .detail-stat-card {
      padding: 14px 16px;
      border-radius: 16px;
      background: rgba(255,255,255,0.88);
      border: 1px solid rgba(45,49,66,0.06);
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.5);
    }
    .detail-stat-label {
      display: block;
      margin-bottom: 8px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: rgba(45,49,66,0.46);
    }
    .detail-stat-value {
      display: block;
      font-size: 24px;
      line-height: 1.05;
      font-weight: 800;
      letter-spacing: -0.7px;
      color: #2D3142;
    }
    .detail-stat-note {
      display: block;
      margin-top: 6px;
      font-size: 12px;
      line-height: 1.45;
      color: rgba(45,49,66,0.54);
    }
    .detail-section .sparkline-box {
      position: relative;
      z-index: 1;
      margin-bottom: 0;
      padding: 0;
      background: transparent;
      border: none;
      box-shadow: none;
    }
    .detail-section .sparkline-box:hover {
      box-shadow: none;
    }
    .detail-section .sparkline-title {
      margin-bottom: 16px;
      font-size: 12px;
      color: rgba(45,49,66,0.52);
    }
    .detail-section .sparkline-canvas {
      height: 220px;
    }
    .detail-callout {
      position: relative;
      z-index: 1;
      padding: 18px;
      border-radius: 18px;
      border: 1px solid rgba(45,49,66,0.08);
      background: linear-gradient(135deg, rgba(255,255,255,0.95), rgba(248,246,241,0.9));
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.6);
    }
    .detail-callout-label {
      display: block;
      margin-bottom: 8px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: rgba(45,49,66,0.44);
    }
    .detail-callout-value {
      display: block;
      font-size: 26px;
      line-height: 1.15;
      font-weight: 800;
      letter-spacing: -0.8px;
      color: #2D3142;
    }
    .detail-callout-note {
      display: block;
      margin-top: 8px;
      font-size: 13px;
      line-height: 1.6;
      color: rgba(45,49,66,0.58);
    }
    .detail-badge-row {
      position: relative;
      z-index: 1;
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin: 16px 0;
    }
    .detail-badge-row .badge {
      border-radius: 999px;
      padding: 6px 10px;
      letter-spacing: 0;
    }
    .detail-pair-grid {
      position: relative;
      z-index: 1;
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
    }
    .detail-pair-card {
      padding: 14px 16px;
      border-radius: 16px;
      background: rgba(255,255,255,0.88);
      border: 1px solid rgba(45,49,66,0.06);
    }
    .detail-pair-label {
      display: block;
      margin-bottom: 8px;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 1px;
      text-transform: uppercase;
      color: rgba(45,49,66,0.46);
    }
    .detail-pair-value {
      display: block;
      font-size: 22px;
      line-height: 1.1;
      font-weight: 800;
      letter-spacing: -0.6px;
      color: #2D3142;
    }
    .detail-pair-note {
      display: block;
      margin-top: 6px;
      font-size: 12px;
      line-height: 1.45;
      color: rgba(45,49,66,0.56);
    }
    .detail-info-grid {
      position: relative;
      z-index: 1;
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 14px;
    }
    .detail-info-card {
      padding: 18px;
      border-radius: 18px;
      background: rgba(255,255,255,0.88);
      border: 1px solid rgba(45,49,66,0.06);
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.5);
    }
    .detail-info-card.wide {
      grid-column: span 2;
    }
    .detail-info-label {
      display: block;
      margin-bottom: 10px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: rgba(45,49,66,0.46);
    }
    .detail-info-value {
      font-size: 14px;
      line-height: 1.7;
      color: rgba(45,49,66,0.92);
      word-break: break-word;
    }
    .detail-info-value strong {
      font-size: 18px;
      letter-spacing: -0.3px;
      color: #2D3142;
    }
    .detail-inline-note {
      display: block;
      margin-top: 6px;
      font-size: 12px;
      line-height: 1.55;
      color: rgba(45,49,66,0.56);
    }
    .detail-footer .btn-row {
      margin-top: 0;
    }
    .detail-footer .record-count {
      margin-top: 0;
    }

    /* ===== 模型使用统计 ===== */
    .model-usage-mini {
      background: rgba(255,255,255,0.06);
      border: 1px solid rgba(255,255,255,0.08);
      border-radius: 10px;
      padding: 10px 12px;
      margin-bottom: 8px;
      text-align: center;
    }
    .model-usage-mini .usage-count {
      font-size: 12px;
      color: rgba(255,255,255,0.6);
      margin-bottom: 4px;
    }
    .model-usage-mini .usage-models {
      font-size: 11px;
      color: rgba(255,255,255,0.4);
      line-height: 1.5;
    }
    #model-usage-overlay {
      position: fixed;
      inset: 0;
      z-index: 2147483647;
      background: rgba(0,0,0,0.5);
      backdrop-filter: blur(8px);
      display: flex;
      align-items: center;
      justify-content: center;
      opacity: 0;
      pointer-events: none;
      transition: opacity 0.3s ease;
    }
    #model-usage-overlay.open {
      opacity: 1;
      pointer-events: auto;
    }
    #model-usage-panel {
      width: min(1100px, 94vw);
      max-width: 1100px;
      max-height: 86vh;
      background:
        radial-gradient(circle at top left, rgba(136,209,138,0.18), transparent 32%),
        radial-gradient(circle at top right, rgba(243,156,18,0.14), transparent 28%),
        linear-gradient(180deg, rgba(248,246,241,0.98), rgba(244,241,233,0.98));
      border-radius: 28px;
      border: 1px solid rgba(45,49,66,0.08);
      box-shadow: 0 28px 90px rgba(0,0,0,0.28);
      overflow: hidden;
      display: flex;
      flex-direction: column;
      transform: translateY(20px) scale(0.95);
      transition: transform 0.3s cubic-bezier(0.25, 0.8, 0.25, 1);
    }
    #model-usage-overlay.open #model-usage-panel {
      transform: translateY(0) scale(1);
    }
    .model-usage-header {
      padding: 22px 28px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      border-bottom: 1px solid rgba(45,49,66,0.08);
      background: rgba(255,255,255,0.46);
      backdrop-filter: blur(16px);
    }
    .model-usage-header span {
      font-size: 18px;
      font-weight: 700;
      color: #2D3142;
      letter-spacing: 0.3px;
    }
    .model-usage-body {
      padding: 24px 28px 28px;
      overflow-y: auto;
      flex: 1;
      color: #2D3142;
    }
    .usage-toolbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 14px;
      margin-bottom: 18px;
      flex-wrap: wrap;
    }
    .usage-toolbar-group {
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
    }
    .usage-toolbar-label {
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 1.2px;
      color: rgba(45,49,66,0.45);
      font-weight: 700;
    }
    .usage-segment {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 6px;
      background: rgba(255,255,255,0.72);
      border: 1px solid rgba(45,49,66,0.08);
      border-radius: 14px;
      box-shadow: 0 10px 30px rgba(45,49,66,0.05);
    }
    .usage-segment button {
      border: none;
      background: transparent;
      color: rgba(45,49,66,0.62);
      font-size: 12px;
      font-weight: 700;
      letter-spacing: 0.2px;
      padding: 10px 14px;
      border-radius: 10px;
      cursor: pointer;
      transition: all 0.2s ease;
    }
    .usage-segment button:hover {
      background: rgba(45,49,66,0.05);
      color: #2D3142;
    }
    .usage-segment button.active {
      background: linear-gradient(135deg, #2D3142, #4F5D75);
      color: #fff;
      box-shadow: 0 8px 20px rgba(45,49,66,0.18);
    }
    .usage-summary-grid {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 14px;
      margin-bottom: 18px;
    }
    .usage-stat-card {
      position: relative;
      overflow: hidden;
      padding: 18px 18px 16px;
      border-radius: 18px;
      background: rgba(255,255,255,0.8);
      border: 1px solid rgba(45,49,66,0.08);
      box-shadow: 0 14px 34px rgba(45,49,66,0.06);
    }
    .usage-stat-card::before {
      content: '';
      position: absolute;
      inset: auto -20px -40px auto;
      width: 110px;
      height: 110px;
      border-radius: 999px;
      background: radial-gradient(circle, rgba(136,209,138,0.2), transparent 68%);
      pointer-events: none;
    }
    .usage-stat-label {
      display: block;
      font-size: 11px;
      color: rgba(45,49,66,0.48);
      text-transform: uppercase;
      letter-spacing: 1.1px;
      margin-bottom: 10px;
      font-weight: 700;
    }
    .usage-stat-value {
      display: block;
      font-size: 30px;
      line-height: 1;
      font-weight: 800;
      color: #2D3142;
      letter-spacing: -0.8px;
      margin-bottom: 8px;
    }
    .usage-stat-note {
      display: block;
      font-size: 12px;
      color: rgba(45,49,66,0.62);
      line-height: 1.5;
    }
    .usage-chart-grid {
      display: grid;
      grid-template-columns: minmax(0, 1.1fr) minmax(0, 1.4fr);
      gap: 16px;
      margin-bottom: 18px;
    }
    .usage-chart-card {
      background: rgba(255,255,255,0.84);
      border: 1px solid rgba(45,49,66,0.08);
      border-radius: 20px;
      padding: 18px;
      box-shadow: 0 14px 34px rgba(45,49,66,0.06);
    }
    .usage-chart-card.full-width {
      grid-column: 1 / -1;
    }
    .usage-chart-head {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: 10px;
      margin-bottom: 14px;
      flex-wrap: wrap;
    }
    .usage-chart-title {
      font-size: 15px;
      font-weight: 700;
      color: #2D3142;
      letter-spacing: 0.2px;
    }
    .usage-chart-subtitle {
      font-size: 12px;
      color: rgba(45,49,66,0.5);
    }
    .usage-pie-layout {
      display: grid;
      grid-template-columns: minmax(180px, 220px) minmax(0, 1fr);
      gap: 18px;
      align-items: center;
    }
    .usage-pie-visual {
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 220px;
    }
    .usage-pie-chart {
      width: 200px;
      height: 200px;
      border-radius: 50%;
      position: relative;
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.36), 0 20px 40px rgba(45,49,66,0.12);
    }
    .usage-pie-chart::after {
      content: '';
      position: absolute;
      inset: 26px;
      border-radius: 50%;
      background: rgba(248,246,241,0.96);
      box-shadow: inset 0 2px 12px rgba(45,49,66,0.08);
    }
    .usage-pie-center {
      position: absolute;
      inset: 0;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      z-index: 1;
      text-align: center;
      padding: 24px;
    }
    .usage-pie-center-value {
      font-size: 28px;
      line-height: 1;
      font-weight: 800;
      color: #2D3142;
      letter-spacing: -0.8px;
    }
    .usage-pie-center-label {
      margin-top: 6px;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 1.2px;
      color: rgba(45,49,66,0.46);
      font-weight: 700;
    }
    .usage-pie-legend {
      display: flex;
      flex-direction: column;
      gap: 10px;
    }
    .usage-pie-legend-item {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 10px;
      align-items: center;
      background: rgba(255,255,255,0.72);
      border: 1px solid rgba(45,49,66,0.06);
      border-radius: 14px;
      padding: 10px 12px;
    }
    .usage-pie-legend-main {
      display: flex;
      align-items: center;
      gap: 8px;
      min-width: 0;
    }
    .usage-pie-legend-main strong {
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      max-width: 100%;
      font-size: 13px;
      color: #2D3142;
    }
    .usage-pie-legend-sub {
      margin-top: 3px;
      font-size: 11px;
      color: rgba(45,49,66,0.5);
    }
    .usage-pie-legend-value {
      text-align: right;
      white-space: nowrap;
    }
    .usage-pie-legend-value strong {
      display: block;
      font-size: 13px;
      color: #2D3142;
    }
    .usage-pie-legend-value span {
      display: block;
      margin-top: 3px;
      font-size: 11px;
      color: rgba(45,49,66,0.5);
    }
    .usage-compare-list {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }
    .usage-compare-row {
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    .usage-compare-meta {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      font-size: 13px;
    }
    .usage-model-name {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      font-weight: 600;
      color: #2D3142;
      min-width: 0;
    }
    .usage-model-name strong {
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      max-width: 260px;
    }
    .usage-model-dot {
      width: 10px;
      height: 10px;
      border-radius: 999px;
      flex: 0 0 auto;
      box-shadow: 0 0 0 4px rgba(0,0,0,0.04);
    }
    .usage-model-value {
      color: rgba(45,49,66,0.66);
      font-weight: 700;
      white-space: nowrap;
    }
    .usage-compare-track {
      height: 12px;
      border-radius: 999px;
      background: rgba(45,49,66,0.08);
      overflow: hidden;
      position: relative;
    }
    .usage-compare-fill {
      position: absolute;
      inset: 0 auto 0 0;
      border-radius: 999px;
      min-width: 10px;
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.28);
    }
    .usage-compare-more {
      margin-top: 12px;
      font-size: 12px;
      color: rgba(45,49,66,0.48);
    }
    .usage-trend-legend {
      display: flex;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
      margin-bottom: 14px;
    }
    .usage-trend-legend-item {
      display: inline-flex;
      align-items: center;
      gap: 7px;
      font-size: 12px;
      color: rgba(45,49,66,0.62);
      max-width: 160px;
    }
    .usage-trend-legend-item span:last-child {
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .usage-trend-scroll {
      overflow-x: auto;
      padding-bottom: 6px;
    }
    .usage-trend-chart {
      display: grid;
      grid-auto-flow: column;
      grid-auto-columns: minmax(42px, 1fr);
      gap: 12px;
      align-items: end;
      min-width: 100%;
      min-height: 260px;
    }
    .usage-trend-day {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 8px;
    }
    .usage-trend-bar-wrap {
      width: 100%;
      height: 180px;
      display: flex;
      align-items: end;
      justify-content: center;
      background:
        linear-gradient(180deg, rgba(45,49,66,0.02), rgba(45,49,66,0.05)),
        repeating-linear-gradient(180deg, transparent, transparent 35px, rgba(45,49,66,0.05) 35px, rgba(45,49,66,0.05) 36px);
      border-radius: 14px;
      padding: 10px 8px;
    }
    .usage-trend-bar {
      width: 100%;
      max-width: 30px;
      min-height: 4px;
      border-radius: 10px;
      overflow: hidden;
      display: flex;
      flex-direction: column-reverse;
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.2), 0 8px 18px rgba(45,49,66,0.1);
    }
    .usage-trend-segment {
      width: 100%;
      min-height: 2px;
    }
    .usage-trend-total {
      font-size: 12px;
      font-weight: 700;
      color: #2D3142;
      line-height: 1;
    }
    .usage-trend-label {
      font-size: 11px;
      color: rgba(45,49,66,0.52);
      letter-spacing: 0.2px;
      white-space: nowrap;
    }
    .usage-section-title {
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 1.2px;
      color: rgba(45,49,66,0.45);
      font-weight: 700;
      margin: 2px 0 12px;
    }
    .usage-overview-table {
      width: 100%;
      border-collapse: separate;
      border-spacing: 0 6px;
      margin-bottom: 18px;
    }
    .usage-overview-table th {
      text-align: left;
      font-size: 11px;
      color: rgba(45,49,66,0.5);
      text-transform: uppercase;
      letter-spacing: 1px;
      padding: 0 12px 6px;
      font-weight: 700;
    }
    .usage-overview-table td {
      background: rgba(255,255,255,0.9);
      padding: 12px;
      font-size: 13px;
      vertical-align: middle;
    }
    .usage-overview-table tr td:first-child {
      border-radius: 12px 0 0 12px;
      width: 44%;
    }
    .usage-overview-table tr td:last-child {
      border-radius: 0 12px 12px 0;
    }
    .usage-share-wrap {
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .usage-share-track {
      flex: 1;
      height: 8px;
      border-radius: 999px;
      background: rgba(45,49,66,0.08);
      overflow: hidden;
    }
    .usage-share-fill {
      height: 100%;
      border-radius: 999px;
    }
    .usage-share-text {
      min-width: 48px;
      text-align: right;
      font-size: 12px;
      color: rgba(45,49,66,0.56);
      font-weight: 700;
    }
    .usage-date-group { margin-bottom: 20px; }
    .usage-date-title {
      font-size: 13px;
      font-weight: 600;
      color: #2D3142;
      margin-bottom: 10px;
      padding-bottom: 6px;
      border-bottom: 1px solid rgba(45,49,66,0.08);
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .usage-date-total {
      font-size: 11px;
      color: rgba(45,49,66,0.5);
      font-weight: 400;
    }
    .usage-table {
      width: 100%;
      border-collapse: separate;
      border-spacing: 0 4px;
    }
    .usage-table th {
      text-align: left;
      font-size: 11px;
      color: rgba(45,49,66,0.5);
      text-transform: uppercase;
      letter-spacing: 1px;
      padding: 6px 12px;
      font-weight: 600;
    }
    .usage-table td {
      background: #fff;
      padding: 10px 12px;
      font-size: 13px;
    }
    .usage-table tr td:first-child {
      border-radius: 8px 0 0 8px;
      font-weight: 500;
    }
    .usage-table tr td:last-child {
      border-radius: 0 8px 8px 0;
      text-align: right;
      font-weight: 600;
      color: #2D3142;
    }
    .usage-empty {
      text-align: center;
      padding: 40px 20px;
      color: rgba(45,49,66,0.4);
      font-size: 14px;
    }
    .usage-clear-btn {
      width: 100%;
      padding: 12px;
      background: #fff;
      border: 1px solid rgba(231,76,60,0.2);
      color: #E74C3C;
      border-radius: 10px;
      cursor: pointer;
      font-size: 13px;
      font-weight: 600;
      transition: all 0.2s;
      margin-top: 10px;
    }
    .usage-clear-btn:hover { background: #fff5f5; border-color: rgba(231,76,60,0.4); }
    @media (max-width: 900px) {
      .detail-grid-shell,
      .detail-info-grid {
        grid-template-columns: 1fr;
      }
      .detail-info-card.wide {
        grid-column: auto;
      }
      .usage-summary-grid,
      .usage-chart-grid {
        grid-template-columns: 1fr;
      }
      .usage-pie-layout {
        grid-template-columns: 1fr;
      }
      .full-body .risk-hero,
      .mini-body .risk-hero {
        grid-template-columns: 1fr;
      }
      .full-body .risk-chip-grid {
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }
      .usage-model-name strong {
        max-width: 170px;
      }
    }
    @media (max-width: 640px) {
      .full-body {
        padding-left: 16px;
        padding-right: 16px;
      }
      .detail-section {
        padding: 18px;
        border-radius: 20px;
      }
      .detail-meter-grid,
      .detail-stat-grid,
      .detail-pair-grid {
        grid-template-columns: 1fr;
      }
      .detail-meter-value {
        font-size: 30px;
      }
      .detail-callout-value {
        font-size: 22px;
      }
      .detail-section .sparkline-canvas {
        height: 180px;
      }
      .btn-row {
        flex-direction: column;
      }
      #model-usage-panel {
        width: 100vw;
        max-width: none;
        max-height: 100vh;
        height: 100vh;
        border-radius: 0;
      }
      .model-usage-header,
      .model-usage-body {
        padding-left: 16px;
        padding-right: 16px;
      }
      .usage-summary-grid {
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }
      .usage-segment {
        width: 100%;
        justify-content: space-between;
      }
      .usage-segment button {
        flex: 1;
        padding-left: 10px;
        padding-right: 10px;
      }
    }
    .btn-stats {
      width: 100%;
      padding: 10px;
      background: rgba(136,209,138,0.15);
      border: 1px solid rgba(136,209,138,0.25);
      color: #88D18A;
      border-radius: 10px;
      cursor: pointer;
      font-size: 13px;
      font-weight: 600;
      transition: all 0.2s;
      margin-top: 4px;
    }
    .btn-stats:hover { background: rgba(136,209,138,0.25); }
  `;

  // ==================== 注入逻辑 ====================
  function initApp() {
    if (document.getElementById('ip-sidebar-toggle')) return;
    if (!document.body) { setTimeout(initApp, 100); return; }

    console.log("🚀 [ChatGPT 降智检测 Pro] DOM已就绪，注入UI...");

    try { GM_addStyle(css); } catch (e) {
      const s = document.createElement('style');
      s.textContent = css;
      document.head.appendChild(s);
    }

    // 侧边栏按钮
    const toggle = document.createElement('div');
    toggle.id = 'ip-sidebar-toggle';
    toggle.innerHTML = `<span class="toggle-icon">🛡️</span><span class="toggle-text">降智检测</span>`;

    // 迷你弹出卡片
    const miniCard = document.createElement('div');
    miniCard.id = 'ip-mini-card';
    miniCard.innerHTML = `<div class="mini-body" id="ip-mini-body"></div>`;

    // 全屏详情遮罩
    const overlay = document.createElement('div');
    overlay.id = 'ip-fullscreen-overlay';
    overlay.innerHTML = `
      <div id="ip-fullscreen-panel">
        <div class="full-header">
          <div class="full-header-inner">
            <div class="full-header-left">
              <span class="h-icon">🛡️</span>
              <span class="h-title">降智检测 Pro</span>
              <span class="h-ver">v3.4</span>
            </div>
            <button class="full-close-btn" id="ip-full-close">✕</button>
          </div>
        </div>
        <div class="full-body" id="ip-full-body"></div>
      </div>
    `;

    // 模型使用统计弹窗
    const modelUsageOverlay = document.createElement('div');
    modelUsageOverlay.id = 'model-usage-overlay';
    modelUsageOverlay.innerHTML = `
      <div id="model-usage-panel">
        <div class="model-usage-header">
          <span>📊 模型使用统计</span>
          <button class="full-close-btn" id="model-usage-close">✕</button>
        </div>
        <div class="model-usage-body" id="model-usage-body"></div>
      </div>
    `;

    document.body.appendChild(toggle);
    document.body.appendChild(miniCard);
    document.body.appendChild(overlay);
    document.body.appendChild(modelUsageOverlay);

    let miniOpen = false;
    const miniBody = miniCard.querySelector('#ip-mini-body');
    const fullBody = overlay.querySelector('#ip-full-body');

    // 缓存最新一次检测数据供全屏展示
    let lastData = null;
    let lastHistory = null;
    let lastAlgo = null;
    const modelUsageState = {
      range: '7d',
      compareMode: 'count',
    };

    window.addEventListener(POW_HISTORY_EVENT, () => {
      if (!lastData) return;
      const score = lastData.fraudScore ?? 0;
      const detectedIP = lastData._chatgptIP || lastData.ip || '';
      const powSnapshot = getLatestPowSnapshot(POW_RECENT_WINDOW_MS) || getLatestPowSnapshot();
      lastAlgo = analyzeHistory(score, detectedIP, powSnapshot);
      if (miniCard.classList.contains('open')) renderMiniResult(lastData, lastHistory, lastAlgo);
      if (overlay.classList.contains('open')) renderFull(lastData, lastHistory, lastAlgo);
    });

    // 切换迷你卡片
    toggle.addEventListener('click', () => {
      miniOpen = !miniOpen;
      miniCard.classList.toggle('open', miniOpen);
    });

    // 点击遮罩背景关闭全屏
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) closeFullscreen();
    });
    document.getElementById('ip-full-close').addEventListener('click', closeFullscreen);

    function closeFullscreen() {
      overlay.classList.remove('open');
    }

    // 模型使用统计弹窗事件
    modelUsageOverlay.addEventListener('click', (e) => {
      if (e.target === modelUsageOverlay) modelUsageOverlay.classList.remove('open');
    });
    document.getElementById('model-usage-close').addEventListener('click', () => {
      modelUsageOverlay.classList.remove('open');
    });

    function openModelUsage() {
      miniOpen = false;
      miniCard.classList.remove('open');
      renderModelUsageTable();
      modelUsageOverlay.classList.add('open');
    }

    function renderModelUsageTable() {
      const usageBody = document.getElementById('model-usage-body');
      const allUsage = loadModelUsage();
      const dates = Object.keys(allUsage).sort().reverse();

      if (dates.length === 0) {
        usageBody.innerHTML = '<div class="usage-empty">📭 暂无使用记录<br><span style="font-size:12px;margin-top:8px;display:block;">发送消息后将自动记录模型使用情况</span></div>';
        return;
      }

      let html = '';
      for (const date of dates) {
        const models = allUsage[date];
        const entries = Object.entries(models).sort((a, b) => b[1] - a[1]);
        const dayTotal = entries.reduce((sum, e) => sum + e[1], 0);
        const dateObj = new Date(date + 'T00:00:00');
        const dateStr = dateObj.getFullYear() + '年' + (dateObj.getMonth() + 1) + '月' + dateObj.getDate() + '日';
        const isToday = date === getLocalDateKey();

        html += '<div class="usage-date-group">';
        html += '<div class="usage-date-title">' + (isToday ? '📅 今天 · ' : '📅 ') + dateStr + '<span class="usage-date-total">共 ' + dayTotal + ' 次</span></div>';
        html += '<table class="usage-table"><thead><tr><th>模型</th><th>使用次数</th></tr></thead><tbody>';
        for (const [model, count] of entries) {
          html += '<tr><td>' + escapeHtml(model) + '</td><td>' + count + ' 次</td></tr>';
        }
        html += '</tbody></table>';
        html += '</div>';
      }

      html += '<button class="usage-clear-btn" id="model-usage-clear">🗑️ 清除所有使用记录</button>';
      usageBody.innerHTML = html;

      document.getElementById('model-usage-clear').addEventListener('click', () => {
        if (confirm('确定要清除所有模型使用记录吗？')) {
          localStorage.removeItem(MODEL_USAGE_KEY);
          renderModelUsageTable();
          updateModelUsageMini();
        }
      });
    }

    function getModelUsageRangeDays(range) {
      if (range === 'today') return 1;
      if (range === '30d') return 30;
      if (range === 'all') return 0;
      return 7;
    }

    function getModelUsageRangeLabel(range) {
      if (range === 'today') return '今天';
      if (range === '30d') return '近 30 天';
      if (range === 'all') return '全部记录';
      return '近 7 天';
    }

    function getUsageDateKeyDaysAgo(daysAgo) {
      const date = new Date();
      date.setHours(12, 0, 0, 0);
      date.setDate(date.getDate() - daysAgo);
      return getLocalDateKey(date);
    }

    function formatUsageDateLabel(dateKey, shortMode) {
      const dateObj = new Date(dateKey + 'T00:00:00');
      if (shortMode) {
        return String(dateObj.getMonth() + 1).padStart(2, '0') + '/' + String(dateObj.getDate()).padStart(2, '0');
      }
      return dateObj.getFullYear() + '年' + (dateObj.getMonth() + 1) + '月' + dateObj.getDate() + '日';
    }

    function getModelColor(model) {
      const palette = ['#88D18A', '#F39C12', '#4F8EF7', '#E67E22', '#E57373', '#7B8CDE', '#3CB7A0', '#A66DD4', '#F4B860', '#5BC0EB'];
      return palette[Number.parseInt(hashString(model), 36) % palette.length];
    }

    function getSelectedUsageDateKeys(allUsage) {
      if (modelUsageState.range === 'all') {
        const allDates = Object.keys(allUsage).sort();
        return allDates.length > 0 ? allDates : [getUsageDateKeyDaysAgo(0)];
      }

      const days = getModelUsageRangeDays(modelUsageState.range);
      const keys = [];
      for (let i = days - 1; i >= 0; i--) keys.push(getUsageDateKeyDaysAgo(i));
      return keys;
    }

    function buildModelUsageSummary(allUsage) {
      const selectedDates = getSelectedUsageDateKeys(allUsage);
      const dailySeries = selectedDates.map((date) => {
        const models = allUsage[date] || {};
        const entries = Object.entries(models).sort((a, b) => b[1] - a[1]);
        const total = entries.reduce((sum, entry) => sum + entry[1], 0);
        return { date, models, entries, total };
      });

      const activeSeries = dailySeries.filter((item) => item.total > 0);
      const modelTotals = {};
      for (const day of dailySeries) {
        for (const [model, count] of Object.entries(day.models)) {
          modelTotals[model] = (modelTotals[model] || 0) + count;
        }
      }

      const modelEntries = Object.entries(modelTotals).sort((a, b) => b[1] - a[1]);
      const totalUsage = modelEntries.reduce((sum, entry) => sum + entry[1], 0);
      const topEntry = modelEntries[0] || null;
      const maxDayTotal = Math.max(1, ...dailySeries.map((item) => item.total));

      return {
        selectedDates,
        dailySeries,
        activeSeries,
        modelEntries,
        totalUsage,
        topEntry,
        maxDayTotal,
        activeDayCount: activeSeries.length,
        modelCount: modelEntries.length,
        averagePerDay: dailySeries.length ? (totalUsage / dailySeries.length) : 0,
      };
    }

    function renderUsageToolbar() {
      const rangeOptions = [
        ['today', '今天'],
        ['7d', '7天'],
        ['30d', '30天'],
        ['all', '全部'],
      ];
      const compareOptions = [
        ['count', '按次数'],
        ['share', '按占比'],
      ];

      let html = '<div class="usage-toolbar">';
      html += '<div class="usage-toolbar-group"><span class="usage-toolbar-label">时间范围</span><div class="usage-segment">';
      for (const [value, label] of rangeOptions) {
        html += '<button type="button" data-usage-range="' + value + '" class="' + (modelUsageState.range === value ? 'active' : '') + '">' + label + '</button>';
      }
      html += '</div></div>';

      html += '<div class="usage-toolbar-group"><span class="usage-toolbar-label">对比方式</span><div class="usage-segment">';
      for (const [value, label] of compareOptions) {
        html += '<button type="button" data-usage-compare="' + value + '" class="' + (modelUsageState.compareMode === value ? 'active' : '') + '">' + label + '</button>';
      }
      html += '</div></div>';
      html += '</div>';
      return html;
    }

    function renderUsageSummaryCards(summary) {
      const topModelName = summary.topEntry ? escapeHtml(summary.topEntry[0]) : '暂无';
      const topModelNote = summary.topEntry ? (summary.topEntry[1] + ' 次') : '还没有使用记录';
      const averageValue = summary.totalUsage > 0 ? summary.averagePerDay.toFixed(1) : '0';

      let html = '<div class="usage-summary-grid">';
      html += '<div class="usage-stat-card"><span class="usage-stat-label">总使用</span><span class="usage-stat-value">' + summary.totalUsage + '</span><span class="usage-stat-note">' + escapeHtml(getModelUsageRangeLabel(modelUsageState.range)) + ' 内累计请求次数</span></div>';
      html += '<div class="usage-stat-card"><span class="usage-stat-label">模型数量</span><span class="usage-stat-value">' + summary.modelCount + '</span><span class="usage-stat-note">这段时间内实际用到的模型数</span></div>';
      html += '<div class="usage-stat-card"><span class="usage-stat-label">主力模型</span><span class="usage-stat-value" style="font-size:22px;">' + topModelName + '</span><span class="usage-stat-note">' + topModelNote + '</span></div>';
      html += '<div class="usage-stat-card"><span class="usage-stat-label">日均频率</span><span class="usage-stat-value">' + averageValue + '</span><span class="usage-stat-note">' + averageValue + ' 次/天，活跃 ' + summary.activeDayCount + ' 天</span></div>';
      html += '</div>';
      return html;
    }

    function renderUsageCompareChart(summary) {
      let html = '<div class="usage-chart-card">';
      html += '<div class="usage-chart-head"><div class="usage-chart-title">模型对比</div><div class="usage-chart-subtitle">' + escapeHtml(getModelUsageRangeLabel(modelUsageState.range)) + ' · ' + (modelUsageState.compareMode === 'share' ? '按使用占比' : '按使用次数') + '</div></div>';

      if (summary.modelEntries.length === 0) {
        html += '<div class="usage-empty" style="padding:28px 8px;">当前区间内还没有模型使用记录</div></div>';
        return html;
      }

      const compareEntries = summary.modelEntries.slice(0, 8);
      const maxCount = compareEntries[0] ? compareEntries[0][1] : 1;
      html += '<div class="usage-compare-list">';

      for (const [model, count] of compareEntries) {
        const color = getModelColor(model);
        const share = summary.totalUsage ? (count / summary.totalUsage * 100) : 0;
        const width = modelUsageState.compareMode === 'share'
          ? Math.max(share, share > 0 ? 6 : 0)
          : Math.max(count / maxCount * 100, count > 0 ? 6 : 0);
        const valueText = modelUsageState.compareMode === 'share'
          ? share.toFixed(1) + '% · ' + count + ' 次'
          : count + ' 次 · ' + share.toFixed(1) + '%';

        html += '<div class="usage-compare-row">';
        html += '<div class="usage-compare-meta"><div class="usage-model-name"><span class="usage-model-dot" style="background:' + color + ';"></span><strong title="' + escapeHtml(model) + '">' + escapeHtml(model) + '</strong></div><div class="usage-model-value">' + valueText + '</div></div>';
        html += '<div class="usage-compare-track"><div class="usage-compare-fill" style="width:' + width.toFixed(2) + '%;background:linear-gradient(90deg,' + color + ', rgba(45,49,66,0.85));"></div></div>';
        html += '</div>';
      }

      html += '</div>';
      if (summary.modelEntries.length > compareEntries.length) {
        html += '<div class="usage-compare-more">还有 ' + (summary.modelEntries.length - compareEntries.length) + ' 个模型未展开，下面的表格里可以看完整数据。</div>';
      }
      html += '</div>';
      return html;
    }

    function renderUsagePieChart(summary) {
      let html = '<div class="usage-chart-card">';
      html += '<div class="usage-chart-head"><div class="usage-chart-title">模型占比扇形图</div><div class="usage-chart-subtitle">用扇形面积看不同模型的使用结构</div></div>';

      if (summary.modelEntries.length === 0 || summary.totalUsage <= 0) {
        html += '<div class="usage-empty" style="padding:28px 8px;">当前区间内还没有可绘制的占比数据</div></div>';
        return html;
      }

      const slices = summary.modelEntries.slice(0, 5).map(([model, count]) => ({
        model,
        count,
        color: getModelColor(model),
      }));
      const otherCount = summary.modelEntries.slice(5).reduce((sum, entry) => sum + entry[1], 0);
      if (otherCount > 0) {
        slices.push({ model: '其他模型', count: otherCount, color: 'rgba(45,49,66,0.35)' });
      }

      let currentPercent = 0;
      const gradientStops = [];
      for (const slice of slices) {
        const percent = slice.count / summary.totalUsage * 100;
        const start = currentPercent;
        currentPercent += percent;
        gradientStops.push(slice.color + ' ' + start.toFixed(2) + '% ' + currentPercent.toFixed(2) + '%');
      }

      html += '<div class="usage-pie-layout">';
      html += '<div class="usage-pie-visual"><div class="usage-pie-chart" style="background:conic-gradient(' + gradientStops.join(', ') + ');"><div class="usage-pie-center"><div class="usage-pie-center-value">' + summary.totalUsage + '</div><div class="usage-pie-center-label">总使用次数</div></div></div></div>';
      html += '<div class="usage-pie-legend">';
      for (const slice of slices) {
        const percent = slice.count / summary.totalUsage * 100;
        html += '<div class="usage-pie-legend-item">';
        html += '<div><div class="usage-pie-legend-main"><span class="usage-model-dot" style="background:' + slice.color + ';"></span><strong title="' + escapeHtml(slice.model) + '">' + escapeHtml(slice.model) + '</strong></div><div class="usage-pie-legend-sub">' + slice.count + ' 次使用</div></div>';
        html += '<div class="usage-pie-legend-value"><strong>' + percent.toFixed(1) + '%</strong><span>' + (summary.topEntry && slice.model === summary.topEntry[0] ? '当前主力模型' : '占总量比例') + '</span></div>';
        html += '</div>';
      }
      html += '</div></div></div>';
      return html;
    }

    function renderUsageTrendChart(summary) {
      let html = '<div class="usage-chart-card full-width">';
      html += '<div class="usage-chart-head"><div class="usage-chart-title">每日趋势</div><div class="usage-chart-subtitle">按天查看模型切换和使用高峰</div></div>';

      if (summary.dailySeries.every((item) => item.total === 0)) {
        html += '<div class="usage-empty" style="padding:28px 8px;">当前区间内没有可绘制的趋势数据</div></div>';
        return html;
      }

      const trendModels = summary.modelEntries.slice(0, 5).map((entry) => entry[0]);
      html += '<div class="usage-trend-legend">';
      for (const model of trendModels) {
        const color = getModelColor(model);
        html += '<div class="usage-trend-legend-item"><span class="usage-model-dot" style="background:' + color + ';"></span><span title="' + escapeHtml(model) + '">' + escapeHtml(model) + '</span></div>';
      }
      if (summary.modelEntries.length > trendModels.length) {
        html += '<div class="usage-trend-legend-item"><span class="usage-model-dot" style="background:rgba(45,49,66,0.35);"></span><span>其他模型</span></div>';
      }
      html += '</div>';

      html += '<div class="usage-trend-scroll"><div class="usage-trend-chart">';
      for (const day of summary.dailySeries) {
        const height = day.total > 0 ? Math.max(6, day.total / summary.maxDayTotal * 100) : 4;
        html += '<div class="usage-trend-day" title="' + escapeHtml(formatUsageDateLabel(day.date, false) + ' · ' + day.total + ' 次') + '">';
        html += '<div class="usage-trend-bar-wrap"><div class="usage-trend-bar" style="height:' + height.toFixed(2) + '%;background:' + (day.total > 0 ? 'rgba(45,49,66,0.06)' : 'rgba(45,49,66,0.04)') + ';">';

        if (day.total > 0) {
          let consumed = 0;
          for (const model of trendModels) {
            const count = day.models[model] || 0;
            if (!count) continue;
            consumed += count;
            html += '<div class="usage-trend-segment" style="flex-basis:' + ((count / day.total) * 100).toFixed(2) + '%;background:' + getModelColor(model) + ';"></div>';
          }
          if (day.total - consumed > 0) {
            html += '<div class="usage-trend-segment" style="flex-basis:' + (((day.total - consumed) / day.total) * 100).toFixed(2) + '%;background:rgba(45,49,66,0.36);"></div>';
          }
        }

        html += '</div></div>';
        html += '<div class="usage-trend-total">' + day.total + '</div>';
        html += '<div class="usage-trend-label">' + formatUsageDateLabel(day.date, true) + '</div>';
        html += '</div>';
      }
      html += '</div></div></div>';
      return html;
    }

    function renderUsageOverviewTable(summary) {
      let html = '<div class="usage-chart-card full-width">';
      html += '<div class="usage-chart-head"><div class="usage-chart-title">模型汇总表</div><div class="usage-chart-subtitle">同一时间范围内直接对比每个模型的次数和占比</div></div>';

      if (summary.modelEntries.length === 0) {
        html += '<div class="usage-empty" style="padding:28px 8px;">当前区间内还没有汇总数据</div></div>';
        return html;
      }

      html += '<table class="usage-overview-table"><thead><tr><th>模型</th><th>次数</th><th>占比</th></tr></thead><tbody>';
      for (const [model, count] of summary.modelEntries) {
        const share = summary.totalUsage ? (count / summary.totalUsage * 100) : 0;
        const color = getModelColor(model);
        html += '<tr>';
        html += '<td><div class="usage-model-name"><span class="usage-model-dot" style="background:' + color + ';"></span><strong title="' + escapeHtml(model) + '">' + escapeHtml(model) + '</strong></div></td>';
        html += '<td style="font-weight:700;color:#2D3142;">' + count + ' 次</td>';
        html += '<td><div class="usage-share-wrap"><div class="usage-share-track"><div class="usage-share-fill" style="width:' + share.toFixed(2) + '%;background:linear-gradient(90deg,' + color + ', rgba(45,49,66,0.82));"></div></div><span class="usage-share-text">' + share.toFixed(1) + '%</span></div></td>';
        html += '</tr>';
      }
      html += '</tbody></table></div>';
      return html;
    }

    function renderUsageDailyGroups(summary) {
      const activeDays = summary.activeSeries.slice().reverse();
      let html = '<div class="usage-section-title">按天明细</div>';

      if (activeDays.length === 0) {
        html += '<div class="usage-empty" style="padding:26px 8px;">当前选择的时间范围内没有使用记录</div>';
        return html;
      }

      for (const day of activeDays) {
        const isToday = day.date === getLocalDateKey();
        html += '<div class="usage-date-group">';
        html += '<div class="usage-date-title">' + (isToday ? '今天 · ' : '') + formatUsageDateLabel(day.date, false) + '<span class="usage-date-total">共 ' + day.total + ' 次</span></div>';
        html += '<table class="usage-table"><thead><tr><th>模型</th><th>次数</th><th>占比</th></tr></thead><tbody>';
        for (const [model, count] of day.entries) {
          const share = day.total ? (count / day.total * 100) : 0;
          html += '<tr><td>' + escapeHtml(model) + '</td><td>' + count + ' 次</td><td>' + share.toFixed(1) + '%</td></tr>';
        }
        html += '</tbody></table>';
        html += '</div>';
      }

      return html;
    }

    function renderModelUsageTable() {
      const usageBody = document.getElementById('model-usage-body');
      const allUsage = loadModelUsage();
      const allDates = Object.keys(allUsage).sort().reverse();

      if (allDates.length === 0) {
        usageBody.innerHTML = '<div class="usage-empty">暂无使用记录<br><span style="font-size:12px;margin-top:8px;display:block;">发送消息后会自动记录模型使用情况</span></div>';
        return;
      }

      const summary = buildModelUsageSummary(allUsage);
      let html = '';
      html += renderUsageToolbar();
      html += renderUsageSummaryCards(summary);
      html += '<div class="usage-chart-grid">';
      html += renderUsageCompareChart(summary);
      html += renderUsagePieChart(summary);
      html += renderUsageTrendChart(summary);
      html += renderUsageOverviewTable(summary);
      html += '</div>';
      html += renderUsageDailyGroups(summary);
      html += '<button class="usage-clear-btn" id="model-usage-clear">清除所有使用记录</button>';
      usageBody.innerHTML = html;

      usageBody.querySelectorAll('[data-usage-range]').forEach((button) => {
        button.addEventListener('click', () => {
          modelUsageState.range = button.dataset.usageRange || '7d';
          renderModelUsageTable();
        });
      });

      usageBody.querySelectorAll('[data-usage-compare]').forEach((button) => {
        button.addEventListener('click', () => {
          modelUsageState.compareMode = button.dataset.usageCompare || 'count';
          renderModelUsageTable();
        });
      });

      document.getElementById('model-usage-clear').addEventListener('click', () => {
        if (confirm('确定要清除所有模型使用记录吗？')) {
          localStorage.removeItem(MODEL_USAGE_KEY);
          renderModelUsageTable();
          updateModelUsageMini();
        }
      });
    }

    function escapeHtml(str) {
      const div = document.createElement('div');
      div.textContent = str;
      return div.innerHTML;
    }

    function openFullscreen() {
      // 关闭迷你卡片
      miniOpen = false;
      miniCard.classList.remove('open');
      // 渲染全屏详情
      if (lastData) renderFull(lastData, lastHistory, lastAlgo);
      overlay.classList.add('open');
    }

    // ========== 风险分级 ==========
    function getRiskLevel(score) {
      // 适配日式禅意色调：抹茶绿、初熟黄、樱花粉、深红
      if (score <= 15) return { text: '特别纯净', sub: '零风险', color: '#88D18A', glow: 'rgba(136,209,138,0.3)' };
      if (score <= 25) return { text: '质量优良', sub: '无风险', color: '#58B160', glow: 'rgba(88,177,96,0.3)' };
      if (score <= 40) return { text: '中等偏好', sub: '需算法研判', color: '#F39C12', glow: 'rgba(243,156,18,0.3)' };
      if (score <= 50) return { text: '中等偏下', sub: '有风险', color: '#E67E22', glow: 'rgba(230,126,34,0.3)' };
      if (score <= 60) return { text: '质量差', sub: '风险极高', color: '#FFB7C5', glow: 'rgba(255,183,197,0.4)' }; // 樱花粉
      if (score <= 70) return { text: '极差', sub: '大概率降智', color: '#E74C3C', glow: 'rgba(231,76,60,0.4)' };
      return { text: '百分百降智', sub: '立即更换', color: '#C0392B', glow: 'rgba(192,57,43,0.5)' };
    }

    // ========== 绘制折线图 ==========
    function drawSparkline(canvasEl, history, riskColor, riskGlow) {
      const ctx = canvasEl.getContext('2d');
      const W = canvasEl.width = canvasEl.offsetWidth * 2;
      const H = canvasEl.height = canvasEl.offsetHeight * 2;
      ctx.scale(2, 2);
      const w = canvasEl.offsetWidth;
      const h = canvasEl.offsetHeight;
      ctx.clearRect(0, 0, w, h);
      const scores = history.map(r => r.score);
      if (scores.length < 2) {
        ctx.fillStyle = 'rgba(45, 49, 66, 0.4)';
        ctx.font = '11px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText('数据收集中...', w / 2, h / 2 + 4);
        return;
      }
      const maxS = 100, minS = 0, padY = 6, padX = 4;
      const usableW = w - padX * 2, usableH = h - padY * 2;
      [
        { from: 0, to: 15, color: 'rgba(136,209,138,0.08)' },
        { from: 15, to: 25, color: 'rgba(88,177,96,0.06)' },
        { from: 25, to: 40, color: 'rgba(243,156,18,0.05)' },
        { from: 40, to: 60, color: 'rgba(255,183,197,0.1)' },
        { from: 60, to: 100, color: 'rgba(231,76,60,0.08)' },
      ].forEach(z => {
        const y1 = padY + (1 - z.to / maxS) * usableH;
        const y2 = padY + (1 - z.from / maxS) * usableH;
        ctx.fillStyle = z.color;
        ctx.fillRect(padX, y1, usableW, y2 - y1);
      });
      const points = scores.map((s, i) => ({
        x: padX + (i / (scores.length - 1)) * usableW,
        y: padY + (1 - (s - minS) / (maxS - minS)) * usableH,
      }));
      const grad = ctx.createLinearGradient(0, 0, 0, h);
      // 使用风险辉光色带有透明度作为渐变顶点
      grad.addColorStop(0, riskGlow.replace(/,0\.[\d]+/, ',0.25'));
      grad.addColorStop(1, 'rgba(248,246,241,0)'); // 融化进底色
      ctx.beginPath();
      ctx.moveTo(points[0].x, h);
      points.forEach(p => ctx.lineTo(p.x, p.y));
      ctx.lineTo(points[points.length - 1].x, h);
      ctx.closePath();
      ctx.fillStyle = grad;
      ctx.fill();
      ctx.beginPath();
      ctx.moveTo(points[0].x, points[0].y);
      for (let i = 1; i < points.length; i++) ctx.lineTo(points[i].x, points[i].y);
      ctx.strokeStyle = riskColor;
      ctx.lineWidth = 2;
      ctx.lineJoin = 'round';
      ctx.stroke();
      const last = points[points.length - 1];
      ctx.beginPath();
      ctx.arc(last.x, last.y, 4, 0, Math.PI * 2);
      ctx.fillStyle = riskColor;
      ctx.fill();
      ctx.beginPath();
      ctx.arc(last.x, last.y, 2, 0, Math.PI * 2);
      ctx.fillStyle = '#fff';
      ctx.fill();
    }

    // ========== 迷你卡片渲染 ==========
    function renderMiniLoading() {
      miniBody.innerHTML = `
        <div class="mini-loading">
          <div class="spinner"></div>
          <span>检测中...</span>
        </div>
      `;
    }

    function renderMiniError(msg) {
      miniBody.innerHTML = `
        <div class="mini-loading" style="color:#fca5a5;">
          <span style="font-size:28px; margin-bottom:8px;">⚠️</span>
          <span>${msg}</span>
          <button class="btn-more" style="margin-top:12px;" id="ip-mini-retry">🔄 重试</button>
        </div>
      `;
      document.getElementById('ip-mini-retry').addEventListener('click', fetchIPInfo);
    }

    function renderMiniResult(data, _history, algo) {
      const score = data.fraudScore ?? 0;
      const risk = getRiskLevel(score);
      const verdictShort = algo.verdict.split('\n')[0]; // 只取第一行
      const powColor = !algo.powAvailable ? 'rgba(255,255,255,0.55)' : (algo.powRisk <= 30 ? '#88D18A' : (algo.powRisk <= 60 ? '#F39C12' : '#FCA5A5'));
      const powMiniHtml = algo.powAvailable
        ? `<div class="mini-ip-line" style="margin-top:6px;color:${powColor};">⚡ PoW ${escapeHtml(algo.powCurrentLabel)} · ${algo.powCurrentDigits} 位 · 风险 ${algo.powRisk}</div>`
        : '';

      miniCard.classList.remove('detail-open');

      const todayTotal = getTodayTotal();

      let modelMiniHtml = '';
      if (todayTotal > 0) {
        modelMiniHtml = `
          <div class="model-usage-mini">
            <div class="usage-count" id="model-usage-today">今日 AI 使用 ${todayTotal} 次</div>
          </div>
        `;
      } else {
        modelMiniHtml = `
          <div class="model-usage-mini">
            <div class="usage-count" id="model-usage-today">今日暂无使用记录</div>
          </div>
        `;
      }

      miniBody.innerHTML = `
        <div class="risk-circle">
          <div class="circle-outer" style="background: radial-gradient(circle, ${risk.glow}, transparent 70%);">
            <div class="circle-ring" style="border-color: ${risk.color};"></div>
            <div class="circle-inner" style="color: ${risk.color};">${score}</div>
          </div>
          <div class="risk-label" style="color: ${risk.color};">${risk.text}</div>
          <div class="risk-sublabel">${risk.sub} · 综合${algo.compositeRisk}</div>
        </div>

        <div class="algo-verdict ${algo.verdictLevel}" style="font-size:12px;padding:10px 12px;">
          ${verdictShort}
        </div>

        <div class="mini-ip-line">${data.ip || '-'} · ${data.country || ''} ${data.city || ''}</div>
        ${powMiniHtml}

        ${modelMiniHtml}

        <button class="btn-more" id="ip-show-more">📖 查看详细分析</button>

        <button class="btn-stats" id="ip-show-stats">📊 模型使用统计</button>

        <button class="btn-more" style="margin-top:6px;background:transparent;border-color:rgba(255,255,255,0.08);font-size:12px;color:rgba(255,255,255,0.5);" id="ip-mini-refresh">🔄 重新检测</button>
      `;

      document.getElementById('ip-show-stats').addEventListener('click', openModelUsage);
      document.getElementById('ip-show-more').addEventListener('click', openFullscreen);
      document.getElementById('ip-mini-refresh').addEventListener('click', fetchIPInfo);
    }

    // ========== 全屏详情渲染 ==========
    function renderDetailMeter(label, value, max, color, subtitle, displayValue, minLabel, maxLabel) {
      const numericValue = Number(value);
      const width = clamp(max > 0 && Number.isFinite(numericValue) ? (numericValue / max) * 100 : 0, 0, 100);
      const valueText = escapeHtml(String(displayValue != null ? displayValue : value));
      return `
        <div class="detail-meter-card">
          <div class="detail-meter-top">
            <span class="detail-meter-label">${escapeHtml(label)}</span>
            <span class="detail-meter-value" style="color:${color};">${valueText}</span>
          </div>
          <div class="detail-meter-sub">${escapeHtml(subtitle)}</div>
          <div class="detail-meter-track">
            <div class="detail-meter-fill" style="width:${width.toFixed(1)}%;background:linear-gradient(90deg, ${color}, rgba(45,49,66,0.82));"></div>
          </div>
          <div class="detail-meter-scale">
            <span>${escapeHtml(String(minLabel != null ? minLabel : 0))}</span>
            <span>${escapeHtml(String(maxLabel != null ? maxLabel : max))}</span>
          </div>
        </div>
      `;
    }

    function renderDetailBar(label, value, max, color, note, displayValue) {
      const numericValue = Number(value);
      const width = clamp(max > 0 && Number.isFinite(numericValue) ? (numericValue / max) * 100 : 0, 0, 100);
      const valueText = escapeHtml(String(displayValue != null ? displayValue : value));
      return `
        <div class="detail-bar-row">
          <div class="detail-bar-meta">
            <span class="detail-bar-label">${escapeHtml(label)}</span>
            <span class="detail-bar-value" style="color:${color};">${valueText}</span>
          </div>
          <div class="detail-bar-track">
            <div class="detail-bar-fill" style="width:${width.toFixed(1)}%;background:linear-gradient(90deg, ${color}, rgba(45,49,66,0.82));"></div>
          </div>
          <div class="detail-bar-note">${escapeHtml(note)}</div>
        </div>
      `;
    }

    function renderDetailStatCard(label, value, note, color) {
      return `
        <div class="detail-stat-card">
          <span class="detail-stat-label">${escapeHtml(label)}</span>
          <span class="detail-stat-value"${color ? ` style="color:${color};"` : ''}>${escapeHtml(String(value))}</span>
          <span class="detail-stat-note">${escapeHtml(note)}</span>
        </div>
      `;
    }

    function renderDetailPairCard(label, value, note, color) {
      return `
        <div class="detail-pair-card">
          <span class="detail-pair-label">${escapeHtml(label)}</span>
          <span class="detail-pair-value"${color ? ` style="color:${color};"` : ''}>${escapeHtml(String(value))}</span>
          <span class="detail-pair-note">${escapeHtml(note)}</span>
        </div>
      `;
    }

    function renderFull(data, history, algo) {
      const score = data.fraudScore ?? 0;
      const isResidential = data.isResidential ?? false;
      const risk = getRiskLevel(score);

      const resColor = isResidential ? 'rgba(136, 209, 138, 0.15)' : 'rgba(231, 76, 60, 0.15)';
      const resText = isResidential ? '✅ 住宅原生' : '❌ 机房IP';
      const resTextColor = isResidential ? '#3e8e41' : '#c0392b';
      const stabilityColor = algo.stability >= 65 ? '#88D18A' : (algo.stability >= 40 ? '#F39C12' : '#E74C3C');

      const confidenceColor = algo.confidence >= 70 ? '#88D18A' : (algo.confidence >= 40 ? '#F39C12' : '#E74C3C');
      const volatilityColor = algo.volatility > 40 ? '#E74C3C' : (algo.volatility > 20 ? '#F39C12' : '#88D18A');
      const powColor = !algo.powAvailable ? 'rgba(45,49,66,0.45)' : (algo.powRisk <= 30 ? '#88D18A' : (algo.powRisk <= 60 ? '#F39C12' : '#E74C3C'));
      const verdictShort = algo.verdict.split('\n')[0];
      const trendText = algo.trend + (algo.trendDelta !== 0 ? ' ' + (algo.trendDelta > 0 ? '+' : '') + algo.trendDelta : '');
      const compositeColor = algo.compositeRisk <= 25 ? '#88D18A' : (algo.compositeRisk <= 40 ? '#F39C12' : '#E74C3C');
      const highRiskRatioColor = algo.recentHighRiskRatio <= 20 ? '#88D18A' : (algo.recentHighRiskRatio <= 45 ? '#F39C12' : '#E74C3C');
      const trendColor = /恶化|⚠|高风险/.test(algo.trend) ? '#E74C3C' : (/改善|✅/.test(algo.trend) ? '#88D18A' : '#F39C12');
      const trendPanelBg = /恶化|⚠|高风险/.test(algo.trend) ? 'rgba(231,76,60,0.12)' : (/改善|✅/.test(algo.trend) ? 'rgba(136,209,138,0.14)' : 'rgba(243,156,18,0.12)');
      const trendPanelBorder = /恶化|⚠|高风险/.test(algo.trend) ? 'rgba(231,76,60,0.22)' : (/改善|✅/.test(algo.trend) ? 'rgba(136,209,138,0.24)' : 'rgba(243,156,18,0.24)');
      const sparklineTitle = `历史风控走势（近 ${Math.min(history.length, MAX_HISTORY)} 次）· EMA ${algo.emaShort}/${algo.emaLong}`;
      const locationText = [data.country, data.regionCode, data.city].filter(Boolean).join(' ') || '暂无定位信息';
      const resLabel = isResidential ? '住宅原生' : '机房 IP';
      const powSummary = algo.powAvailable ? `${algo.powCurrentLabel} · ${algo.powCurrentDigits} 位` : '暂无样本';
      const powHint = algo.powAvailable
        ? `低难度占比 ${algo.powLowRatio}% · ${algo.powFresh ? '当前样本较新' : '当前样本偏旧'}`
        : '尚未捕获 chat-requirements 的 PoW 样本';
      const actualIpNote = data._chatgptIP && data._chatgptIP !== data.ip
        ? `
            <span class="detail-inline-note" style="color:#d68910;">真实出口 IP：<strong>${escapeHtml(data._chatgptIP)}</strong></span>
            ${!data._isProxied ? '<span class="detail-inline-note" style="color:#c0392b;">IPPure 不支持指定 IP 查询，当前评分可能与真实出口存在偏差。</span>' : ''}
          `
        : (data._chatgptIP
          ? '<span class="detail-inline-note" style="color:#3e8e41;">检测 IP 与 ChatGPT 真实出口一致。</span>'
          : '<span class="detail-inline-note">暂未确认 ChatGPT 的真实出口 IP。</span>');
      const patternBadges = [
        algo.sawtoothDetected
          ? '<span class="badge" style="background:rgba(231,76,60,0.1);color:#c0392b;">锯齿波动</span>'
          : '<span class="badge" style="background:rgba(136,209,138,0.1);color:#3e8e41;">无锯齿波动</span>',
        algo.stairDetected
          ? '<span class="badge" style="background:rgba(231,76,60,0.1);color:#c0392b;">阶梯恶化</span>'
          : '<span class="badge" style="background:rgba(136,209,138,0.1);color:#3e8e41;">无阶梯恶化</span>',
        algo.currentHighRiskStreak > 0
          ? `<span class="badge" style="background:rgba(231,76,60,0.1);color:#c0392b;">连续高风险 x${algo.currentHighRiskStreak}</span>`
          : '<span class="badge" style="background:rgba(136,209,138,0.1);color:#3e8e41;">当前无连续高风险</span>',
        algo.ipSwitches > 0
          ? `<span class="badge" style="background:rgba(243,156,18,0.1);color:#d68910;">IP 切换 x${algo.ipSwitches}</span>`
          : '<span class="badge" style="background:rgba(45,49,66,0.08);color:rgba(45,49,66,0.7);">IP 稳定</span>',
        algo.powAvailable
          ? `<span class="badge" style="background:${algo.powRisk <= 30 ? 'rgba(136,209,138,0.12)' : (algo.powRisk <= 60 ? 'rgba(243,156,18,0.12)' : 'rgba(231,76,60,0.12)')};color:${powColor};">PoW ${powSummary}</span>`
          : '<span class="badge" style="background:rgba(45,49,66,0.08);color:rgba(45,49,66,0.7);">PoW 暂无样本</span>'
      ].join('');
      const overviewBars = [
        renderDetailBar('稳定性', algo.stability, 100, stabilityColor, '越高越稳定，说明历史分数更平顺'),
        renderDetailBar('置信度', algo.confidence, 100, confidenceColor, '越高代表当前结论越可信', `${algo.confidence}%`),
        renderDetailBar('波动指数', algo.volatility, 100, volatilityColor, '越高越容易出现大起大落'),
        renderDetailBar('近期高风险占比', algo.recentHighRiskRatio, 100, highRiskRatioColor, '最近一段记录中高风险会话所占比例', `${algo.recentHighRiskRatio}%`),
        renderDetailBar('PoW Risk', algo.powAvailable ? algo.powRisk : 0, 100, powColor, 'Derived from chat-requirements difficulty; higher usually means weaker entry quality', algo.powAvailable ? algo.powRisk : '-')
      ].join('');
      const statCards = [
        renderDetailStatCard('衰减均值', algo.weightedAvg, '更看重最近几次会话表现'),
        renderDetailStatCard('历史均分', algo.avgScore, '全部记录的平均风险分'),
        renderDetailStatCard('EMA 短 / 长', `${algo.emaShort} / ${algo.emaLong}`, '短线和长线的趋势对比'),
        renderDetailStatCard('区间跳跃', algo.zoneJumps, '风险区间切换的频繁程度'),
        renderDetailStatCard('历史峰值', algo.peakScore, '完整记录中的最高分'),
        renderDetailStatCard('近期峰值', algo.recentPeakScore, '最近阶段的最高分'),
        renderDetailStatCard('标准差 σ', algo.stdDev, '整体离散程度'),
        renderDetailStatCard('鲁棒波动', algo.robustStd, '去极值后的稳定性参考'),
        renderDetailStatCard('PoW Current', powSummary, powHint, powColor),
        renderDetailStatCard('PoW Risk', algo.powAvailable ? algo.powRisk : '-', 'Merged into the composite score with moderate weight', powColor)
      ].join('');
      const pairCards = [
        renderDetailPairCard('连续高风险', algo.currentHighRiskStreak, '当前连续落在高风险区的会话数', algo.currentHighRiskStreak >= 2 ? '#E74C3C' : '#2D3142'),
        renderDetailPairCard('IP 切换', algo.ipSwitches, '观察期内出口 IP 的切换次数', algo.ipSwitches > 0 ? '#F39C12' : '#2D3142'),
        renderDetailPairCard('有效样本', algo.effectiveSamples, '考虑时间衰减后的有效样本量'),
        renderDetailPairCard('当前 IP 记录', algo.currentIPHistory.length, '当前出口 IP 已累计的记录数'),
        renderDetailPairCard('PoW Samples', algo.powSampleCount, 'Recent PoW samples used in scoring', algo.powAvailable ? '#2D3142' : 'rgba(45,49,66,0.45)'),
        renderDetailPairCard('PoW Low Ratio', algo.powAvailable ? (algo.powLowRatio + '%') : '-', 'Share of recent samples at 3 hex digits or lower', powColor)
      ].join('');

      fullBody.innerHTML = `
        <div class="risk-hero">
          <div class="risk-circle">
            <div class="circle-outer" style="background: radial-gradient(circle, ${risk.glow.replace(/,0\.[\d]+/, ',0.1')}, transparent 70%);">
              <div class="circle-ring" style="border-color: ${risk.color};"></div>
              <div class="circle-inner" style="color: ${risk.color};">${score}</div>
            </div>
          </div>
          <div class="risk-hero-main">
            <div class="risk-kicker">Risk Overview</div>
            <div class="risk-hero-top">
              <div>
                <div class="risk-hero-title" style="color:${risk.color};">${risk.text}</div>
                <div class="risk-hero-subtitle">${risk.sub} · IPPure 当前风险评分 ${score}</div>
              </div>
              <div class="risk-tag-row">
                <span class="risk-tag" style="background:${risk.glow.replace(/0\.[\d]+/, '0.10')};border-color:${risk.glow.replace(/0\.[\d]+/, '0.18')};color:${risk.color};">综合 ${algo.compositeRisk}</span>
                <span class="risk-tag" style="background:${resColor};border-color:transparent;color:${resTextColor};">${resLabel}</span>
              </div>
            </div>
            <div class="risk-hero-note">${verdictShort}</div>
            <div class="risk-chip-grid">
              <div class="risk-chip">
                <span class="risk-chip-label">稳定性</span>
                <span class="risk-chip-value" style="color:${stabilityColor};">${algo.stability}</span>
                <span class="risk-chip-hint">历史分数的平顺程度</span>
              </div>
              <div class="risk-chip">
                <span class="risk-chip-label">置信度</span>
                <span class="risk-chip-value" style="color:${confidenceColor};">${algo.confidence}%</span>
                <span class="risk-chip-hint">当前结论的把握程度</span>
              </div>
              <div class="risk-chip">
                <span class="risk-chip-label">波动指数</span>
                <span class="risk-chip-value" style="color:${volatilityColor};">${algo.volatility}</span>
                <span class="risk-chip-hint">越高越不稳定</span>
              </div>
              <div class="risk-chip">
                <span class="risk-chip-label">趋势</span>
                <span class="risk-chip-value" style="font-size:20px;color:${trendColor};">${trendText}</span>
                <span class="risk-chip-hint">近期变化方向</span>
              </div>
            </div>
          </div>
        </div>

        <div class="detail-dashboard">
          <div class="detail-grid-shell">
            <section class="detail-section">
              <div class="detail-section-head">
                <div>
                  <span class="detail-section-kicker">Overview</span>
                  <div class="detail-section-title">核心指标总览</div>
                </div>
                <div class="detail-section-note">把最关键的风险分和稳定性集中展示，先看结论，再看是否值得继续使用当前节点。</div>
              </div>
              <div class="detail-meter-grid">
                ${renderDetailMeter('当前风险分', score, 100, risk.color, `IPPure 实时评分 · 当前位于 ${zoneName(scoreToZone(score))} 区间`, null, '低', '高')}
                ${renderDetailMeter('综合风险分', algo.compositeRisk, 100, compositeColor, '结合历史走势、波动和模式后的综合判断', null, '稳', '险')}
              </div>
              <div class="detail-bar-list">
                ${overviewBars}
              </div>
            </section>

            <section class="detail-section">
              <div class="detail-section-head">
                <div>
                  <span class="detail-section-kicker">Decision</span>
                  <div class="detail-section-title">算法判定</div>
                </div>
                <div class="detail-section-note">保留原来的结论文案，但把辅助指标压缩进统一侧栏，减少视觉噪音。</div>
              </div>
              <div class="algo-verdict ${algo.verdictLevel}">
                <div class="algo-title">波动算法智能研判 v5 · PoW</div>
                ${algo.verdict.replace(/\n/g, '<br/>')}
              </div>
              <div class="detail-stat-grid">
                ${statCards}
              </div>
            </section>
          </div>

          <div class="detail-grid-shell">
            <section class="detail-section">
              <div class="detail-section-head">
                <div>
                  <span class="detail-section-kicker">Trend</span>
                  <div class="detail-section-title">历史走势</div>
                </div>
                <div class="detail-section-note">保留折线图，但让它成为单独的主区块，避免被散碎信息打断阅读。</div>
              </div>
              <div class="sparkline-box">
                <div class="sparkline-title">${sparklineTitle}</div>
                <canvas class="sparkline-canvas" id="ip-sparkline-full"></canvas>
              </div>
            </section>

            <section class="detail-section">
              <div class="detail-section-head">
                <div>
                  <span class="detail-section-kicker">Pattern</span>
                  <div class="detail-section-title">趋势与模式</div>
                </div>
                <div class="detail-section-note">把原本分散的模式识别结果收拢到一起，方便快速判断是在恶化、恢复还是横盘。</div>
              </div>
              <div class="detail-callout" style="background:linear-gradient(135deg, ${trendPanelBg}, rgba(255,255,255,0.96));border-color:${trendPanelBorder};">
                <span class="detail-callout-label">趋势方向</span>
                <span class="detail-callout-value" style="color:${trendColor};">${trendText}</span>
                <span class="detail-callout-note">趋势变化量 ${algo.trendDelta > 0 ? '+' : ''}${algo.trendDelta}，近期高风险占比 ${algo.recentHighRiskRatio}%</span>
              </div>
              <div class="detail-badge-row">
                ${patternBadges}
              </div>
              <div class="detail-pair-grid">
                ${pairCards}
              </div>
            </section>
          </div>

          <section class="detail-section">
            <div class="detail-section-head">
              <div>
                <span class="detail-section-kicker">Network</span>
                <div class="detail-section-title">出口网络信息</div>
              </div>
              <div class="detail-section-note">网络信息改成清晰的键值卡片，避免像表格一样横向挤压。</div>
            </div>
            <div class="detail-info-grid">
              <div class="detail-info-card wide">
                <span class="detail-info-label">ChatGPT 出口 IP</span>
                <div class="detail-info-value">
                  <strong>${escapeHtml(data.ip || '-')}</strong>
                  ${actualIpNote}
                </div>
              </div>
              <div class="detail-info-card">
                <span class="detail-info-label">位置</span>
                <div class="detail-info-value">${escapeHtml(locationText)}</div>
              </div>
              <div class="detail-info-card">
                <span class="detail-info-label">ASN / 运营商</span>
                <div class="detail-info-value">
                  <strong>AS${escapeHtml(String(data.asn || '-'))}</strong>
                  <span class="detail-inline-note">${escapeHtml(data.asOrganization || '-')}</span>
                </div>
              </div>
              <div class="detail-info-card">
                <span class="detail-info-label">IP 属性</span>
                <div class="detail-info-value" style="display:flex;flex-wrap:wrap;gap:8px;">
                  <span class="badge" style="background:${resColor};color:${resTextColor};">${resLabel}</span>
                  <span class="badge" style="background:rgba(45,49,66,0.08);color:rgba(45,49,66,0.72);">${data.isBroadcast ? '广播 IP' : '非广播 IP'}</span>
                </div>
              </div>
            </div>
          </section>

          <div class="detail-footer">
            <div class="btn-row">
              <button class="btn-refresh" id="ip-full-refresh">🔄 重新检测</button>
              <button class="btn-clear" id="ip-full-clear">🗑️ 清除历史</button>
            </div>
            <div class="record-count">累计 ${algo.totalRecords} 条记录 · ${algo.totalSessions} 个会话 · σ=${algo.stdDev} · 当前 IP 记录 ${algo.currentIPHistory.length} 条</div>
          </div>
        </div>
      `;

      document.getElementById('ip-full-refresh').addEventListener('click', () => { closeFullscreen(); fetchIPInfo(); });
      document.getElementById('ip-full-clear').addEventListener('click', () => {
        if (confirm('确定要清除所有历史检测记录吗？清除后算法将重新积累数据。')) {
          localStorage.removeItem(STORAGE_KEY);
          closeFullscreen();
          fetchIPInfo();
        }
      });

      requestAnimationFrame(() => {
        const canvas = document.getElementById('ip-sparkline-full');
        if (canvas) drawSparkline(canvas, history, risk.color, risk.glow);
      });
      return;

      fullBody.innerHTML = `
        <!-- 风险圆环 -->
        <div class="risk-circle">
          <div class="circle-outer" style="background: radial-gradient(circle, ${risk.glow.replace(/,0\.[\d]+/, ',0.1')}, transparent 70%);">
            <div class="circle-ring" style="border-color: ${risk.color};"></div>
            <div class="circle-inner" style="color: ${risk.color};">${score}</div>
          </div>
          <div class="risk-label" style="color: ${risk.color};">${risk.text}</div>
          <div class="risk-sublabel">${risk.sub} · IPPure风控分</div>
        </div>

        <!-- 风险标尺 -->
        <div class="risk-ruler">
          <div class="ruler-title">📊 风险等级标尺</div>
          <div class="ruler-bar">
            <div class="ruler-marker" style="left: ${Math.min(100, score)}%; border-color: ${risk.color};"></div>
          </div>
          <div class="ruler-labels">
            <span>0 纯净</span><span>15</span><span>25</span><span>40</span><span>50</span><span>60</span><span>70</span><span>100 降智</span>
          </div>
        </div>

        <!-- 算法判定 -->
        <div class="algo-verdict ${algo.verdictLevel}">
          <div class="algo-title">🧠 波动算法智能研判 v5 · PoW</div>
          ${algo.verdict.replace(/\n/g, '<br/>')}
        </div>

        <!-- 综合风险评分 -->
        <div class="risk-ruler">
          <div class="ruler-title">🎯 综合风险评分（算法计算）</div>
          <div class="ruler-bar">
            <div class="ruler-marker" style="left: ${Math.min(100, algo.compositeRisk)}%; border-color: ${algo.compositeRisk <= 25 ? '#88D18A' : algo.compositeRisk <= 40 ? '#F39C12' : '#E74C3C'};"></div>
          </div>
          <div class="ruler-labels">
            <span>0 安全</span><span>25</span><span>40</span><span>60</span><span>100 危险</span>
          </div>
        </div>

        <!-- 算法指标 -->
        <div class="algo-grid">
          <div class="algo-metric">
            <div class="algo-metric-value" style="color: ${algo.compositeRisk <= 25 ? '#88D18A' : algo.compositeRisk <= 40 ? '#F39C12' : '#E74C3C'};">${algo.compositeRisk}</div>
            <div class="algo-metric-label">综合评分</div>
          </div>
          <div class="algo-metric">
            <div class="algo-metric-value" style="color: ${stabilityColor};">${algo.stability}</div>
            <div class="algo-metric-label">稳定性</div>
          </div>
          <div class="algo-metric">
            <div class="algo-metric-value" style="color: ${algo.confidence >= 70 ? '#88D18A' : algo.confidence >= 40 ? '#F39C12' : '#E74C3C'};">${algo.confidence}%</div>
            <div class="algo-metric-label">置信度</div>
          </div>
          <div class="algo-metric">
            <div class="algo-metric-value" style="color: ${algo.volatility > 40 ? '#E74C3C' : (algo.volatility > 20 ? '#F39C12' : '#88D18A')};">${algo.volatility}</div>
            <div class="algo-metric-label">波动指数</div>
          </div>
        </div>

        <!-- 详细指标 -->
        <div class="algo-grid">
          <div class="algo-metric">
            <div class="algo-metric-value">${algo.weightedAvg}</div>
            <div class="algo-metric-label">衰减加权均值</div>
          </div>
          <div class="algo-metric">
            <div class="algo-metric-value">${algo.avgScore}</div>
            <div class="algo-metric-label">历史均分</div>
          </div>
          <div class="algo-metric">
            <div class="algo-metric-value" style="font-size:18px;">${algo.emaShort} / ${algo.emaLong}</div>
            <div class="algo-metric-label">EMA短/长</div>
          </div>
          <div class="algo-metric">
            <div class="algo-metric-value">${algo.zoneJumps}</div>
            <div class="algo-metric-label">区间跳跃</div>
          </div>
        </div>

        <!-- 模式检测 -->
        <div class="info-grid">
          <div class="info-item">
            <div class="info-item-header">📈 趋势方向</div>
            <div class="info-item-value">${algo.trend}${algo.trendDelta !== 0 ? ' <span style="font-size:11px;opacity:0.6;">(' + (algo.trendDelta > 0 ? '+' : '') + algo.trendDelta + ')</span>' : ''}</div>
          </div>
          <div class="info-item">
            <div class="info-item-header">🔍 模式检测</div>
            <div class="info-item-value" style="flex-wrap:wrap;gap:8px;">
              ${algo.sawtoothDetected ? '<span class="badge" style="background:rgba(231,76,60,0.1);color:#c0392b;">⚡ 锯齿波动</span>' : '<span class="badge" style="background:rgba(136,209,138,0.1);color:#3e8e41;">✓ 无锯齿</span>'}
              ${algo.stairDetected ? '<span class="badge" style="background:rgba(231,76,60,0.1);color:#c0392b;">📶 阶梯恶化</span>' : '<span class="badge" style="background:rgba(136,209,138,0.1);color:#3e8e41;">✓ 无阶梯</span>'}
              ${algo.ipSwitches > 0 ? '<span class="badge" style="background:rgba(243,156,18,0.1);color:#d68910;">🔄 IP切换×' + algo.ipSwitches + '</span>' : ''}
            </div>
          </div>
          <div class="info-item">
            <div class="info-item-header">📊 峰值分析</div>
            <div class="info-item-value">历史最高 ${algo.peakScore} · 近期最高 ${algo.recentPeakScore}</div>
          </div>
        </div>

        <!-- 波动折线图 -->
        <div class="sparkline-box">
          <div class="sparkline-title">📉 历史风控分走势 (近${Math.min(history.length, MAX_HISTORY)}次 · EMA ${algo.emaShort}/${algo.emaLong})</div>
          <canvas class="sparkline-canvas" id="ip-sparkline-full"></canvas>
        </div>

        <!-- IP详细信息 -->
        <div class="info-grid">
          <div class="info-item">
            <div class="info-item-header">🌐 ChatGPT 出口 IP${data._chatgptIP ? ' (已校准)' : ''}</div>
            <div class="info-item-value" style="flex-direction:column;align-items:flex-start;gap:6px;">
              <span style="font-weight:600;">${data.ip || '-'}</span>
              ${data._chatgptIP && data._chatgptIP !== data.ip ? `
                <span style="font-size:11px;color:#d68910;display:flex;align-items:center;gap:4px;"><span>⚠️</span> 实际ChatGPT出口: ${data._chatgptIP}</span>
                ${!data._isProxied ? '<span style="font-size:10px;color:#c0392b;">⛔ IPPure不支持指定IP查询，当前结果可能与实际出口不一致</span>' : ''}
              ` : (data._chatgptIP ? '<span style="font-size:11px;color:#3e8e41;display:flex;align-items:center;gap:4px;"><span>✅</span> 检测IP与出口一致</span>' : '<span style="font-size:11px;color:rgba(45,49,66,0.5);display:flex;align-items:center;gap:4px;"><span>⚠️</span> 未能确认ChatGPT出口IP</span>')}
            </div>
          </div>
          <div class="info-item">
            <div class="info-item-header">📍 位置信息</div>
            <div class="info-item-value">${data.country || ''} ${data.regionCode || ''} ${data.city || ''}</div>
          </div>
          <div class="info-item">
            <div class="info-item-header">📡 ASN & 运营商</div>
            <div class="info-item-value" style="flex-direction:column;align-items:flex-start;gap:4px;">
              <span style="font-weight:600;">AS${data.asn || '-'}</span>
              <span style="font-size:12px;color:rgba(45,49,66,0.6);">${data.asOrganization || '-'}</span>
            </div>
          </div>
          <div class="info-item">
            <div class="info-item-header">🛡️ IP 属性</div>
            <div class="info-item-value" style="margin-top:4px;flex-wrap:wrap;gap:6px;">
              <span class="badge" style="background:${resColor};color:${resTextColor};">${resText}</span>
              <span class="badge" style="background:rgba(45, 49, 66, 0.05);color:rgba(45, 49, 66, 0.6);">${data.isBroadcast ? '广播IP' : '非广播IP'}</span>
            </div>
          </div>
        </div>

        <div class="btn-row">
          <button class="btn-refresh" id="ip-full-refresh">🔄 重新检测</button>
          <button class="btn-clear" id="ip-full-clear">🗑️ 清除历史</button>
        </div>

        <div class="record-count">累计 ${algo.totalRecords} 条记录 · ${algo.totalSessions} 个会话 · σ=${algo.stdDev} · 当前IP记录${algo.currentIPHistory.length}条</div>
      `;

      const fullHero = document.createElement('div');
      fullHero.className = 'risk-hero';
      fullHero.innerHTML = `
        <div class="risk-circle">
          <div class="circle-outer" style="background: radial-gradient(circle, ${risk.glow.replace(/,0\.[\d]+/, ',0.1')}, transparent 70%);">
            <div class="circle-ring" style="border-color: ${risk.color};"></div>
            <div class="circle-inner" style="color: ${risk.color};">${score}</div>
          </div>
        </div>
        <div class="risk-hero-main">
          <div class="risk-kicker">Risk Overview</div>
          <div class="risk-hero-top">
            <div>
              <div class="risk-hero-title" style="color:${risk.color};">${risk.text}</div>
              <div class="risk-hero-subtitle">${risk.sub} · IPPure 风控分 ${score}</div>
            </div>
            <div class="risk-tag-row">
              <span class="risk-tag" style="background:${risk.glow.replace(/0\.[\d]+/, '0.10')};border-color:${risk.glow.replace(/0\.[\d]+/, '0.18')};color:${risk.color};">综合 ${algo.compositeRisk}</span>
              <span class="risk-tag" style="background:${resColor};border-color:transparent;color:${resTextColor};">${resText}</span>
            </div>
          </div>
          <div class="risk-hero-note">${verdictShort}</div>
          <div class="risk-chip-grid">
            <div class="risk-chip">
              <span class="risk-chip-label">稳定性</span>
              <span class="risk-chip-value" style="color:${stabilityColor};">${algo.stability}</span>
              <span class="risk-chip-hint">历史稳定程度</span>
            </div>
            <div class="risk-chip">
              <span class="risk-chip-label">置信度</span>
              <span class="risk-chip-value" style="color:${confidenceColor};">${algo.confidence}%</span>
              <span class="risk-chip-hint">当前结论把握</span>
            </div>
            <div class="risk-chip">
              <span class="risk-chip-label">波动指数</span>
              <span class="risk-chip-value" style="color:${volatilityColor};">${algo.volatility}</span>
              <span class="risk-chip-hint">越高越不稳定</span>
            </div>
            <div class="risk-chip">
              <span class="risk-chip-label">趋势</span>
              <span class="risk-chip-value" style="font-size:20px;">${trendText}</span>
              <span class="risk-chip-hint">近期变化方向</span>
            </div>
          </div>
        </div>
      `;

      const oldFullRisk = fullBody.querySelector('.risk-circle');
      const firstRuler = fullBody.querySelector('.risk-ruler');
      if (firstRuler) {
        fullBody.insertBefore(fullHero, firstRuler);
      } else {
        fullBody.prepend(fullHero);
      }
      if (oldFullRisk) oldFullRisk.remove();

      document.getElementById('ip-full-refresh').addEventListener('click', () => { closeFullscreen(); fetchIPInfo(); });
      document.getElementById('ip-full-clear').addEventListener('click', () => {
        if (confirm('确定要清除所有历史检测记录吗？清除后算法将重新积累数据。')) {
          localStorage.removeItem(STORAGE_KEY);
          closeFullscreen();
          fetchIPInfo();
        }
      });

      requestAnimationFrame(() => {
        const canvas = document.getElementById('ip-sparkline-full');
        if (canvas) drawSparkline(canvas, history, risk.color, risk.glow);
      });
    }

    // ========== 统一结果处理 ==========
    function renderResult(data) {
      const score = data.fraudScore ?? 0;
      const detectedIP = data._chatgptIP || data.ip || '';
      const powSnapshot = getLatestPowSnapshot(POW_RECENT_WINDOW_MS) || getLatestPowSnapshot();

      const history = addRecord(score, detectedIP);
      const algo = analyzeHistory(score, detectedIP, powSnapshot);

      // 缓存供全屏使用
      lastData = data;
      lastHistory = history;
      lastAlgo = algo;

      // 渲染迷你卡片
      renderMiniResult(data, history, algo);
    }

    // ========== 获取ChatGPT真实出口IP ==========
    // 通过 Cloudflare cdn-cgi/trace 端点拿到浏览器访问 chatgpt.com 时的真实出口IP
    // 这个请求走浏览器代理，和ChatGPT看到的IP完全一致
    function getChatGPTRealIP() {
      return fetch('https://chatgpt.com/cdn-cgi/trace', { cache: 'no-store' })
        .then(r => r.text())
        .then(text => {
          // 解析 Cloudflare trace 格式: ip=x.x.x.x
          const match = text.match(/^ip=(.+)$/m);
          if (match && match[1]) return match[1].trim();
          throw new Error('无法解析IP');
        });
    }

    // ========== 请求 ==========
    function renderLoading() { renderMiniLoading(); }
    function renderError(msg) { renderMiniError(msg); }

    function fetchIPInfo() {
      renderMiniLoading();

      // 第一步：获取 ChatGPT 真实出口 IP
      getChatGPTRealIP().then(chatgptIP => {
        console.log('[降智检测] ChatGPT出口IP:', chatgptIP);

        // 第二步：用该IP查询IPPure风控信息
        GM_xmlhttpRequest({
          method: 'GET',
          url: 'https://my.ippure.com/v1/info?ip=' + encodeURIComponent(chatgptIP),
          responseType: 'json',
          timeout: 15000,
          onload(res) {
            if (res.status === 200 && res.response) {
              // 附加ChatGPT真实IP标记
              res.response._chatgptIP = chatgptIP;
              res.response._isProxied = true;
              renderResult(res.response);
            } else {
              // 如果带IP参数不支持，回退到不带参数（直连IPPure）
              console.warn('[降智检测] 带IP查询失败，尝试回退...');
              GM_xmlhttpRequest({
                method: 'GET',
                url: 'https://my.ippure.com/v1/info',
                responseType: 'json',
                timeout: 15000,
                onload(res2) {
                  if (res2.status === 200 && res2.response) {
                    res2.response._chatgptIP = chatgptIP;
                    res2.response._isProxied = false;
                    renderResult(res2.response);
                  } else {
                    renderError('API 请求失败：' + res2.status);
                  }
                },
                onerror() { renderError('网络错误，获取IP信息失败'); },
                ontimeout() { renderError('请求超时，请稍后重试'); },
              });
            }
          },
          onerror() { renderError('网络错误，获取IP信息失败'); },
          ontimeout() { renderError('请求超时，请稍后重试'); },
        });
      }).catch(err => {
        console.warn('[降智检测] Cloudflare trace失败，回退到直接查询', err);
        // 回退：直接查IPPure（可能IP不同但至少能用）
        GM_xmlhttpRequest({
          method: 'GET',
          url: 'https://my.ippure.com/v1/info',
          responseType: 'json',
          timeout: 15000,
          onload(res) {
            if (res.status === 200 && res.response) {
              res.response._chatgptIP = null;
              res.response._isProxied = false;
              renderResult(res.response);
            } else {
              renderError('API 请求失败：' + res.status);
            }
          },
          onerror() { renderError('网络错误，获取IP信息失败'); },
          ontimeout() { renderError('请求超时，请稍后重试'); },
        });
      });
    }

    // ========== 启动 ==========
    fetchIPInfo();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initApp);
  } else {
    initApp();
  }
  setTimeout(initApp, 1500);

})();
