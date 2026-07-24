"use strict";

(function () {
  const githubUrl = "https://github.com/Steven-ZYC";
  const language = (navigator.language || "en").toLowerCase();
  const isChinese = language.startsWith("zh");
  const documentLanguage = isChinese ? "zh" : "en";

  document.documentElement.dataset.lang = documentLanguage;
  document.documentElement.lang = isChinese ? "zh-CN" : "en";
  document.title = isChinese
    ? "Steven Zhang Yancheng | 网站施工中"
    : "Steven Zhang Yancheng | Website Under Construction";

  let seconds = 8;
  const zhCounter = document.getElementById("countdown-zh");
  const enCounter = document.getElementById("countdown-en");
  const timer = window.setInterval(function () {
    seconds -= 1;
    if (zhCounter) zhCounter.textContent = String(seconds);
    if (enCounter) enCounter.textContent = String(seconds);
    if (seconds <= 0) {
      window.clearInterval(timer);
      window.location.assign(githubUrl);
    }
  }, 1000);

  window.addEventListener("click", function () {
    window.clearInterval(timer);
    const footer = document.querySelector("footer");
    if (footer) {
      footer.textContent = isChinese
        ? "已取消自动跳转。"
        : "Automatic redirect cancelled.";
    }
  }, { once: true });
}());
