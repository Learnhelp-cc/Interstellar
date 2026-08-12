// home.js
let inFrame;

try {
  inFrame = window !== top;
} catch (e) {
  inFrame = true;
}

if (!localStorage.getItem("ab")) {
  localStorage.setItem("ab", true);
}

const shouldOpenPopup = !inFrame && !navigator.userAgent.includes("Firefox") && localStorage.getItem("ab") === "true" && location.pathname === "/";

if (shouldOpenPopup) {
  const popup = open("about:blank", "_blank");
  setTimeout(() => {
    if (!popup || popup.closed) {
      alert("Please allow popups for this site so we can open the destination in a clean tab without adding it to your browsing history.");
      return;
    }

    const doc = popup.document;
    const iframe = doc.createElement("iframe");
    const style = iframe.style;
    const link = doc.createElement("link");

    const siteName = localStorage.getItem("siteName") || "My Drive - Google Drive";
    const icon = localStorage.getItem("icon") || "https://ssl.gstatic.com/docs/doclist/images/drive_2022q3_32dp.png";

    doc.title = siteName;
    link.rel = "icon";
    link.href = icon;

    iframe.src = location.href;
    style.position = "fixed";
    style.top = style.bottom = style.left = style.right = 0;
    style.border = style.outline = "none";
    style.width = style.height = "100%";

    doc.head.appendChild(link);
    doc.body.appendChild(iframe);

    const pLink = localStorage.getItem(encodeURI("pLink")) || getRandomUrl();
    location.replace(pLink);

    const script = doc.createElement("script");
    script.textContent = `
      window.onbeforeunload = function (event) {
        const confirmationMessage = 'Leave Site?';
        (event || window.event).returnValue = confirmationMessage;
        return confirmationMessage;
      };
    `;
    doc.head.appendChild(script);
  }, 1500);
}
// Splash texts
const SplashT = [
  "Over 8 Million Users since 2023",
  "Fastest growing proxy server",
  "Made by xBubbo modded by ilikepancakes.ink",
  "big smoke",
  "Thanks for using the site",
  "slaap lekker en laat de bedwantsen je niet bijten :3",
  "you wouldn't download a car",
  "check out my website ilikepancakes.ink",
  "Check out the settings page",
  ":3",
];

let SplashI = Math.floor(Math.random() * SplashT.length);
const SplashE = document.getElementById("splash");

function US() {
  SplashI = (SplashI + 1) % SplashT.length;
  if (SplashE) SplashE.innerText = SplashT[SplashI];
}

if (SplashE) {
  SplashE.innerText = SplashT[SplashI];
  SplashE.addEventListener("click", US);
}

// Rotating Welcome Messages
const welcomeMessages = [
  "Welcome",        // English
  "Bienvenido",     // Spanish
  "Welkom",         // Dutch
  "Willkommen",     // German
  "Bienvenue",      // French
  "Välkommen",      // Swedish
  "ようこそ",       // Japanese
  "환영합니다",     // Korean
  "欢迎",           // Chinese
  "Добро пожаловать", // Russian
  "أهلا وسهلا",     // Arabic
  "მოგესალმებით",   // Georgian
  "Bem-vindo",      // Portuguese
  "Dobrodošli",     // Croatian
  "Vitajte",        // Slovakian
  "Benvenuto",      // Italian
  "Καλώς ήρθατε",   // Greek
  "स्वागतम्",       // Nepali
  "ברוך הבא",       // Hebrew
  "Sugeng rawuh",   // Javanese
  "Chào mừng",      // Vietnamese
  "A jaɓɓorgo",     // Fulfulde
  "Ir ka koy",      // Zarma
  "Marhaban"        // Tamasheq
];

// Merry Christmas messages in different languages
const christmasMessages = [
  "Merry Christmas",        // English
  "Feliz Navidad",          // Spanish
  "Vrolijk Kerstfeest",     // Dutch
  "Frohe Weihnachten",      // German
  "Joyeux Noël",            // French
  "God Jul",                // Swedish
  "メリークリスマス",       // Japanese
  "메리 크리스마스",        // Korean
  "圣诞快乐",               // Chinese
  "Счастливого Рождества",  // Russian
  "عيد ميلاد مجيد",         // Arabic
  "საუკეთესო შობა",         // Georgian
  "Feliz Natal",            // Portuguese
  "Sretni Božić",           // Croatian
  "Veselé Vianoce",         // Slovakian
  "Buon Natale",            // Italian
  "Καλά Χριστούγεννα",     // Greek
  "शुभ क्रिसमस",           // Nepali
  "חג מולד שמח",            // Hebrew
  "Sugeng Natal",           // Javanese
  "Chúc mừng Giáng sinh",   // Vietnamese
  "Kirismasu njoddi",       // Fulfulde
  "Ir ka koy Kirismasu",    // Zarma
  "Marhaban Kirismasu"      // Tamasheq
];

let currentMessageIndex = 0;
const welcomeText = document.getElementById("welcome-text");

function rotateWelcomeMessage() {
  if (!welcomeText) {
    return;
  }
  
  // Check if it's December (month 11) or January (month 0)
  const currentMonth = new Date().getMonth();
  const isChristmasSeason = currentMonth === 11 || currentMonth === 0;
  
  // Fade out
  welcomeText.classList.add("fade-out");

  setTimeout(() => {
    if (isChristmasSeason) {
      // Cycle through Merry Christmas messages in different languages
      welcomeText.textContent = christmasMessages[currentMessageIndex];
      currentMessageIndex = (currentMessageIndex + 1) % christmasMessages.length;
    } else {
      // Cycle through normal welcome messages in different languages
      welcomeText.textContent = welcomeMessages[currentMessageIndex];
      currentMessageIndex = (currentMessageIndex + 1) % welcomeMessages.length;
    }

    // Fade in
    welcomeText.classList.remove("fade-out");
  }, 1000);
}

document.addEventListener('DOMContentLoaded', function() {
  if (welcomeText) {
    rotateWelcomeMessage();
    setInterval(rotateWelcomeMessage, 3000);
  }
});

// Random URL
function getRandomUrl() {
  const randomUrls = [
    "https://kahoot.it",
    "https://classroom.google.com",
    "https://drive.google.com",
    "https://google.com",
    "https://docs.google.com",
    "https://slides.google.com",
    "https://www.nasa.gov",
    "https://blooket.com",
    "https://clever.com",
    "https://edpuzzle.com",
    "https://khanacademy.org",
    "https://wikipedia.org",
    "https://dictionary.com",
  ];
  return randomUrls[randRange(0, randomUrls.length)];
}

function randRange(min, max) {
  return Math.floor(Math.random() * (max - min) + min);
}

// Wave background is handled in CSS only; the old particle system has been removed.
