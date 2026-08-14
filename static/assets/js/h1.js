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
  "欢迎",           // Chinese (Simplified)
  "歡迎",           // Chinese (Traditional / Cantonese)
  "Добро пожаловать", // Russian
  "أهلا وسهلا",     // Arabic
  "მოဂესალმებით",   // Georgian
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
  "Marhaban",       // Tamasheq
  "Ласкаво просимо",     // Ukrainian
  "Сардэчна запрашаем",  // Belarusian
  "Добре дошли",         // Bulgarian
  "Добродошли",          // Serbian (Cyrillic)
  "Добредојдовте",       // Macedonian
  "Қош келдіңіз",        // Kazakh (Cyrillic)
  "Кош келиңиз",        // Kyrgyz
  "Хуш омадед",         // Tajik
  "Тавтай морил",        // Mongolian (Cyrillic)
  "स्वागत है",       // Hindi
  "স্বাগতম",         // Bengali
  "خوش آمدید",       // Urdu / Persian
  "நல்வரவு",        // Tamil
  "స్వాగతం",       // Telugu
  "സ്വാഗതം",       // Malayalam
  "ಸ್ವಾಗತ",        // Kannada
  "सुस्वागतम",     // Marathi
  "સ્વાગત છે",      // Gujarati
  "ਜੀ ਆਇਆਂ ਨੂੰ",   // Punjabi
  "සාදරයෙන් පිළිගන්නවා", // Sinhala
  "ยินดีต้อนรับ",    // Thai
  "Selamat datang",  // Indonesian / Malay
  "Maligayang pagdating", // Filipino / Tagalog
  "ស្វាគមន៍",      // Khmer
  "ຍິນດີຕ້ອນຮັບ",    // Lao
  "ကြိုဆိုပါတယျ",   // Burmese
  "Benvindo",        // Tetum
  "Xush kelibsiz",   // Uzbek
  "Hoş geldiňiz",    // Turkmen
  "Xoş gəlmisiniz",  // Azerbaijani
  "Բարի ալուստ",     // Armenian
  "Hoş geldiniz",    // Turkish
  "Bi xêr hatî",     // Kurdish (Kurmanji)
  "بەخێربێن",        // Kurdish (Sorani)
  "བྱོན་པ་ལེགས།",    // Tibetan
  "خۇش كېلىپسىز",    // Uyghur
  "Witaj",          // Polish
  "Vítejte",        // Czech
  "Üdvözöljük",     // Hungarian
  "Bun venit",      // Romanian
  "Velkommen",      // Danish / Norwegian
  "Tervetuloa",     // Finnish
  "Tere tulemast",  // Estonian
  "Laipni lūdzam",  // Latvian
  "Sveiki atvykę",  // Lithuanian
  "Fáilte",         // Irish
  "Croeso",         // Welsh
  "Fàilte",         // Scottish Gaelic
  "Ongietorri",     // Basque
  "Benvingut",      // Catalan
  "Benvindo",       // Galician
  "Benvengut",      // Occitan
  "Merħba",         // Maltese
  "Mire se vini",   // Albanian
  "Wollkomm",       // Luxembourgish
  "Velkomin",       // Icelandic
  "Bæntschit",      // Romansh
  "Benvegni",       // Venetian
  "Benvignù",       // Piedmontese
  "Degemer mat",    // Breton
  "Fostaiid",       // Sami (Northern)
  "Karibu",         // Swahili
  "E kaabo",        // Yoruba
  "Nnọọ",           // Igbo
  "Barke",          // Hausa
  "Akwaaba",        // Twi (Akan)
  "Siyakwamukela",  // Zulu
  "Re a go amogela",// Tswana
  "Molweni",        // Xhosa
  "Wamkelekile",    // Southern Sotho
  "Soyez le bienvenue", // Lingala (often shared with French)
  "Muyoobii",       // Oromo
  "እንኳን ደህና መጣችሁ", // Amharic
  "Marhaban",       // Somali
  "Murakaza neza",  // Kinyarwanda / Kirundi
  "Kalibu",         // Luganda
  "Tongai",         // Shona
  "Tongai",         // Malagasy
  "Bienvenido",     // Quechua (Often borrows / "Allichu")
  "Tere",           // Guarani ("Maitei")
  "Chaltmay",       // Mapudungun
  "Kamisaraki",     // Aymara
  "Yá'át'ééh",      // Navajo
  "Halito",         // Choctaw
  "Kwe",            // Mi'kmaq
  "Tunngasugit",    // Inuktitut
  "Failte",         // Michif
  "Haere mai",      // Maori
  "Aloha",          // Hawaiian
  "Bula",           // Fijian
  "Amiang",         // Marshallese
  "Malo e lelei",   // Tongan
  "Talofa",         // Samoan
  "Kia orana",      // Cook Islands Maori
  "Kaselehlie",     // Pohnpeian
  "Hafa adai",      // Chamorro
  "Welkam",         // Bislama
  "Maimai",         // Tok Pisin
  "Sugeng rawuh",   // Sundanese ("Wilujeng sumping")
  "Mabuhay",        // Tagalog (Greeting/Welcome variant)
  "Fiandem",        // Balinese ("Om Swastyastu")
  "Sua s'dei",      // Khmer (Alternative formal)
  "Shagatam",       // Assamese ("স্বাগতম")
  "स्वागतम्",       // Sanskrit
  "স্বাগতম",         // Manipuri (Meitei)
  "رحمـــت",        // Pashto ("پخير راغلاست")
  "Khush Aamdeed",  // Balochi
  "خوش آمدید"        // Sindhi
];

const workersOfTheWorldUniteMessages = [
  "Workers of the world, unite!",
  "Trabajadores del mundo, ¡uníos!",
  "Werknemers van de wereld, verenigt u!",
  "Arbeiter der Welt, vereinigt euch!",
  "Ouvriers du monde, unissons-nous !",
  "Arbetare i världen, enas er!",
  "世界の労働者よ、団結せよ！",
  "세계의 노동자여, 단결하라!",
  "世界的工人，团结起来！",
  "世界工人，團結起來！",
  "Рабочие всего мира, соединяйтесь!",
  "عمال العالم، متحدوا!",
  "მსოფლიოს მუშები, ერთდით!",
  "Trabalhadores do mundo, unam-se!",
  "Radnici svijeta, ujedinite se!",
  "Robotníci sveta, spojte sa!",
  "Lavoratori del mondo, unitevi!",
  "Εργάτες του κόσμου, ενωθείτε!",
  "दुनिया के श्रमिकों, एक हो जाओ!",
  "פועלי העולם, התאחדו!",
  "Pekerja jagad, manunggal!",
  "Công nhân trên thế giới, đoàn kết!",
  "Робітники всіх країн, єднайтеся!",
  "Рабочыя ўсіх краін, аб'яднайцеся!",
  "Работници от целия свят, обединявайте се!",
  "स्वागत है",
  "বিশ্বের শ্রমিকরা, একত্রিত হও!",
  "عالم کے کارکنو، متحد ہو جاو!",
  "உலக தொழிலாளர்கள், ஒன்றுபடுங்கள்!",
  "ప్రపంచ పనివార్లు, కలిసి గట్టిగా ఉండండి!",
  "ലോക തൊഴിലാളികളേ, ഐക്യമാർകമായി ഒരുമിക്കൂ!",
  "ವಿಶ್ವದ ಕಾರ್ಮಿಕರೇ, ಒಗ್ಗೂಡಿ!",
  "जगातील कामगारांनो, एका हो!",
  "દુનિયાના મજૂરોએ, એક થાવ!",
  "ਪ੍ਰਪੰਚ ਦੇ ਮਜ਼ਦੂਰ, ਇਕਠੇ ਹੋ ਜਾਓ!",
  "ලොවයේ කම්කරුවෝ, එක්වෙන්න!",
  "คนงานทั้งโลก, จับมือร่วมกัน!",
  "Pekerja dunia, bersatu!",
  "Mga manggagawa ng mundo, magkaisa!",
  "កម្មករទូទាំងពិភពលោក, ចូលរួមគ្នា!",
  "ຜູ້ງານທົ່ວໂລກ, ຮວມເຂົ້າກັນ!",
  "ကမၻာ့အလုပ္သမားမ်ား၊ တစုတစည္းတည္းျဖစ္ပါ!",
  "Dünya işçileri, birleşin!",
  "İşçilər, dünya birliyinə!",
  "İşçi dünya, birləşin!",
  "Բոլոր աշխատավորներ, միավորվեք!",
  "Robotnicy świata, łączcie się!",
  "Dělníci světa, spojte se!",
  "A világ munkásai, egyesüljetek!",
  "Muncitorii lumii, uniți-vă!",
  "Verdens arbejdere, foren jer!",
  "Maailman työläiset, yhdistykää!",
  "Maailma töölised, ühinege!",
  "Darbinieki pasaulē, apvienojieties!",
  "Pasaulio darbininkai, susijunkite!",
  "Oibrithe an domhain, éirigh le chéile!",
  "Gweithwyr y byd, uno!",
  "Luchd an t-saoghail, aonadh!",
  "Munduko langileak, elkartu!",
  "Treballadors del món, uneix-te!",
  "Trabalhadores do mundo, unanse!",
  "Traballadurs dal mond, unids!",
  "Ħaddiema tad-dinja, ingħaqqu!",
  "Punët e botës, bashkohuni!",
  "Weltarbechter, vereenegt Iech!",
  "Heimssinna, sameinist!",
  "Lavoradurs dal mund, uni te!",
  "Travailleurs du monde, unissez-vous!",
  "Wafanyakazi wa dunia, united!",
  "Ndị na-arụ ọrụ nke ụwa, jikọta onwe unu!",
  "Abahimu b'isi, babatane!",
  "Abeadole aye, darapọ!",
  "Ukunzima w'isi, hlangana!",
  "Vashandi vepasirose, mubatane!",
  "Abeadole aye, darapọ!",
  "Maaijra, one!",
  "Pekerja dunia, bersatu!",
  "Mga manggagawa ng mundo, magkaisa!",
  "Tāngata o te ao, whakakotahi!",
  "Pūna'ā o ka honua, e hui pū!",
  "Na ka po'e o ke ao, e hui!",
  "Maka halian, e tolonga!",
  "Dasigni o'ao, uja!",
  "Kaitangata o te ao, e mahi tahi!",
  "Oibrithe an domhain, aontaigh!",
  "Lavoratori di tutte le nazioni, unitevi!",
  "Workers of the world, unite!"
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
  "圣诞快乐",               // Chinese (Simplified)
  "聖誕快樂",               // Chinese (Traditional / Cantonese: Sing1 daan3 faai3 lok6)
  "Счастливого Рождества",  // Russian
  "عيد ميلاد مجيد",         // Arabic
  "საუკეთესო შობა",         // Georgian
  "Feliz Natal",            // Portuguese
  "Sretan Božić",           // Croatian
  "Veselé Vianoce",         // Slovakian
  "Buon Natale",            // Italian
  "Καλά Χριστούγεννα",     // Greek
  "शुभ क्रिसमस",           // Nepali
  "חג מולד שמח",            // Hebrew
  "Sugeng Natal",           // Javanese
  "Chúc mừng Giáng sinh",   // Vietnamese
  "Kirismasu njoddi",       // Fulfulde
  "Ir ka koy Kirismasu",    // Zarma
  "Marhaban Kirismasu",      // Tamasheq
  "З Різдвом Христовим!",    // Ukrainian
  "З Калядамі!",            // Belarusian
  "Весела Коледа",          // Bulgarian
  "Срећан Божић",           // Serbian (Cyrillic)
  "Среќен Божик",           // Macedonian
  "Рождество құтты болсын",  // Kazakh
  "Рождество кут болсун",   // Kyrgyz
  "Мавлуди Исо муборак",    // Tajik
  "Зул сарын мэнд хүргэе",  // Mongolian
  "Wesołych Świąt",         // Polish
  "Veselé Vánoce",          // Czech
  "Boldog Karácsonyt",      // Hungarian
  "Crăciun Fericit",        // Romanian
  "Glædelig Jul",           // Danish
  "God Jul",                // Norwegian
  "Hyvää Joulua",           // Finnish
  "Häid Jõule",             // Estonian
  "Priecīgus Ziemassvētkus",// Latvian
  "Su šventomis Kalėdomis", // Lithuanian
  "Nollaig Shona Duit",     // Irish
  "Nadolig Llawen",         // Welsh
  "Nollaig Chridheil",      // Scottish Gaelic
  "Zorionak eta Urte Berri On", // Basque
  "Bon Nadal",               // Catalan / Occitan
  "Feliz Nadal",            // Galician
  "Il-Milied it-Tajjeb",    // Maltese
  "Gëzuar Krishtlindjet",   // Albanian
  "Schéi Chrëschtdag",      // Luxembourgish
  "Gleðileg Jól",           // Icelandic
  "Bellas Festas da Nadal", // Romansh
  "Buon Nadale",            // Sardinian
  "Nedeleg Mat",            // Breton
  "Buorrit Juovllat",        // Northern Sami
  "क्रिसमस की शुभकामनाएं",// Hindi
  "শুভ বড়দিন",              // Bengali
  "کرسمس مبارک",            // Urdu
  "இனிய கிறிஸ்துமஸ் வாழ்த்துகள்", // Tamil
  "క్రిస్మస్ శుభాకాంక్షలు", // Telugu
  "ക്രിസ്മസ് ആശംസകൾ",    // Malayalam
  "ಕ್ರಿಸ್ಮಸ್ ಹಬ್ಬದ ಶುಭಾಶಯಗಳು", // Kannada
  "शुभ नाताळ",              // Marathi
  "નાતાલની શુભકામનાઓ",     // Gujarati
  "ਮੈਰੀ ਕ੍ਰਿਸਮਸ",            // Punjabi
  "සුබ නත්තලක් වේවා",     // Sinhala
  "สุขสันต์วันคริสต์มาส",   // Thai
  "Selamat Hari Natal",     // Indonesian / Malay
  "Maligayang Pasko",       // Filipino / Tagalog
  "រីករាយថ្ងៃបុណ្យណូអែល",    // Khmer
  "ສຸກສັນວັນຄຣິດສະມາດ",    // Lao
  "မေရီခရစ္စမတ်",           // Burmese
  "Ksolok ba Natal",        // Tetum
  "Rojdestvo muborak",      // Uzbek
  "Rojdestwo baýramyňyz gutly bolsun", // Turkmen
  "Milad bayramınız mübarək", // Azerbaijani
  "Շնորհավոր Սուրբ Ծնունդ", // Armenian
  "Mutlu Noeller",          // Turkish
  "Krîsmes pîroz be",       // Kurdish (Kurmanji)
  "کریسمس پیرۆز بێت",       // Kurdish (Sorani)
  "کریسمس مبارک",            // Persian / Farsi
  "ཡེ་ཤུའི་འཁྲུངས་སྐར་ལ་བཀྲ་ཤིས་བདེ་ལེགས།", // Tibetan
  "مەسىھنىڭ تۇغۇلغان كۈنىگە مۇبارەك بولسۇن", // Uyghur
  "Wilujeng Natal",         // Sundanese
  "Selamat Natal",          // Balinese
  "ক্রিসমাসৰ শুভেচ্ছা",      // Assamese
  "क्रिसमसस्य शुभकामनाः",   // Sanskrit
  "Krismasi Njema",         // Swahili
  "E ku odun keresimesi",   // Yoruba
  "Ekeresimesi Oma",        // Igbo
  "Barka da Kirsimeti",     // Hausa
  "Afishapa",               // Twi (Akan)
  "Ukrisimusi omnandi",     // Zulu
  "Masego a Keresemose",    // Tswana
  "Krismesi emnandi",       // Xhosa
  "Keresemese e monate",     // Southern Sotho
  "Joyeux Noël",            // Lingala
  "Baga Ayyaana Qillee Gaarii Isiniif Haa Ta'u", // Oromo
  "መልካም বড়ገና",            // Amharic
  "Kristmas Wanaagsan",     // Somali
  "Noheli Nziza",           // Kinyarwanda / Kirundi
  "Sekukulu Enungi",         // Luganda
  "Kisimusi Sere",          // Shona
  "Tratry ny Krismasy",     // Malagasy
  "Sumaq Navidad",          // Quechua
  "Vy'apave Marangatu Ára", // Guarani
  "Küme Tripantu Che",       // Mapudungun
  "Suma Jach'a Uru",        // Aymara
  "Yá'át'ééh Késhmish",     // Navajo
  "Yukpa Késhmish",         // Choctaw
  "Welálin Nuwel",          // Mi'kmaq
  "Quviasuvviksiutsiarit",   // Inuktitut
  "Meri Kirihimete",        // Maori
  "Mele Kalikimaka",        // Hawaiian
  "Meno Kalikimaka",        // Fijian
  "Monōņōņ kōņān Kūrjin-m̧ōş", // Marshallese
  "Kilisimasi Fiefia",      // Tongan
  "La Maopia Le Kerisimasi",// Samoan
  "Kia koa i te Raa Kiritimiti", // Cook Islands Maori
  "Kirisimas Mwahmwa",      // Pohnpeian
  "Felissat Nabidåt",       // Chamorro
  "Apinun we long Krismas", // Bislama / Tok Pisin
  "Ia orana i te Noera"      // Tahitian
];


let currentMessageIndex = 0;
const welcomeText = document.getElementById("welcome-text");

function rotateWelcomeMessage() {
  if (!welcomeText) {
    return;
  }

  const today = new Date();
  const currentMonth = today.getMonth();
  const currentDay = today.getDate();
  const isSovietUnionFoundingDay = currentMonth === 11 && currentDay === 30;
  const isChristmasSeason = !isSovietUnionFoundingDay && (currentMonth === 11 || currentMonth === 0);

  // Fade out
  welcomeText.classList.add("fade-out");

  setTimeout(() => {
    if (isSovietUnionFoundingDay) {
      welcomeText.textContent = workersOfTheWorldUniteMessages[currentMessageIndex];
      currentMessageIndex = (currentMessageIndex + 1) % workersOfTheWorldUniteMessages.length;
    } else if (isChristmasSeason) {
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
