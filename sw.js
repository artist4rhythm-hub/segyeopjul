// 세 겹 줄 — 화면 파일만 저장해 두는 서비스 워커 (데이터는 Firebase가 따로 관리)
// 파일을 고쳐 다시 올릴 때는 아래 버전 숫자를 하나 올려 주세요.
const VERSION = 'sgj-v3';
const FILES = [
  './', './index.html', './css/app.css', './js/app.js', './js/content.js', './js/firebase-config.js',
  './manifest.webmanifest', './icons/icon-192.png', './icons/icon-512.png', './icons/beams.svg',
];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(VERSION).then((c) => c.addAll(FILES)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== VERSION).map((k) => caches.delete(k))))
    .then(() => self.clients.claim()));
});

// 내 사이트 파일: 인터넷 먼저, 안 되면 저장본. 다른 주소(Firebase, 글꼴)는 건드리지 않음.
self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.origin !== self.location.origin) return;
  e.respondWith(
    fetch(e.request).then((res) => {
      const copy = res.clone();
      caches.open(VERSION).then((c) => c.put(e.request, copy));
      return res;
    }).catch(() => caches.match(e.request).then((r) => r || caches.match('./index.html')))
  );
});
