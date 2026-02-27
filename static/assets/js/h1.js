// home.js
console.log('🏠 DEBUG: Starting h1.js initialization...');

let inFrame;

try {
  inFrame = window !== top;
  console.log('🏠 DEBUG: Frame detection result:', inFrame);
} catch (e) {
  inFrame = true;
  console.log('🏠 DEBUG: Frame detection error, assuming in frame:', e);
}

if (!localStorage.getItem("ab")) {
  localStorage.setItem("ab", true);
  console.log('🏠 DEBUG: Set default ab setting to true');
}

console.log('🏠 DEBUG: ab setting:', localStorage.getItem("ab"));
console.log('🏠 DEBUG: Firefox detection:', navigator.userAgent.includes("Firefox"));

  if (!inFrame && !navigator.userAgent.includes("Firefox") && localStorage.getItem("ab") === "true") {
  console.log('🏠 DEBUG: Opening about:blank popup...');
  const popup = open("about:blank", "_blank");
  setTimeout(() => {
    if (!popup || popup.closed) {
      console.log('🏠 DEBUG: Popup failed to open or was closed');
      alert("Please allow popups for this site. Doing so will allow us to open the site in a about:blank tab and preventing this site from showing up in your history. You can turn this off in the site settings.");
    } else {
      console.log('🏠 DEBUG: Popup opened successfully');
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
      console.log('🏠 DEBUG: Redirecting to:', pLink);
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
    }
  }, 2000);
} else {
  console.log('🏠 DEBUG: Skipping popup - conditions not met');
  console.log('  - inFrame:', inFrame);
  console.log('  - Firefox:', navigator.userAgent.includes("Firefox"));
  console.log('  - ab setting:', localStorage.getItem("ab"));
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

console.log('🏠 DEBUG: Splash element found:', SplashE);

function US() {
  SplashI = (SplashI + 1) % SplashT.length;
  SplashE.innerText = SplashT[SplashI];
  console.log('🏠 DEBUG: Splash text changed to:', SplashT[SplashI]);
}

if (SplashE) {
  SplashE.innerText = SplashT[SplashI];
  SplashE.addEventListener("click", US);
  console.log('🏠 DEBUG: Splash text set to:', SplashT[SplashI]);
} else {
  console.error('🏠 DEBUG: Splash element not found!');
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

console.log('🏠 DEBUG: Welcome text element found:', welcomeText);

function rotateWelcomeMessage() {
  if (!welcomeText) {
    console.error('🏠 DEBUG: Welcome text element not found!');
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
    console.log('🏠 DEBUG: Welcome message updated to:', welcomeText.textContent);
  }, 1000); // Half of transition time
}

// Start rotating after page load
document.addEventListener('DOMContentLoaded', function() {
  if (welcomeText) {
    rotateWelcomeMessage();
    setInterval(rotateWelcomeMessage, 3000); // Change every 3 seconds
    console.log('🏠 DEBUG: Welcome message rotation started');
  } else {
    console.error('🏠 DEBUG: Cannot start welcome message rotation - element not found');
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
