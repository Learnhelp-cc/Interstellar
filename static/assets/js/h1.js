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
  "Workers of the world, unite!",                // English
  "Trabajadores del mundo, ¡uníos!",             // Spanish
  "Werknemers van de wereld, verenigt u!",       // Dutch
  "Proletarier aller Länder, vereinigt euch!",   // German
  "Ouvriers du monde, unissez-vous !",           // French
  "Arbetare i hela världen, förena er!",         // Swedish
  "万国の労働者よ、団結せよ！",                     // Japanese
  "세계의 노동자여, 단결하라!",                       // Korean
  "全世界无产者，联合起来！",                      // Chinese (Simplified)
  "全世界無產者，聯合起來！",                      // Chinese (Traditional)
  "Пролетарии всех стран, соединяйтесь!",        // Russian
  "يا عمال العالم، اتحدوا!",                       // Arabic
  "პროლეტარებო ყველა ქვეყნისა, შეერთდით!",       // Georgian
  "Trabalhadores do mundo, unam-se!",            // Portuguese
  "Proleteri svih zemalja, ujedinite se!",        // Croatian / Serbian / Bosnian
  "Proletári всех krajín, spojte sa!",           // Slovakian
  "Lavoratori di tutto il mondo, unitevi!",      // Italian
  "Προλετάριοι όλων των χωρών, ενωθείτε!",       // Greek
  "संसारका मजदूरहरू, एक होऔं!",                   // Nepali
  "פועלי כל الأרצות, התאחדו!",                     // Hebrew
  "Pekerja jagad, manunggal!",                   // Javanese
  "Vô sản toàn thế giới, liên hiệp lại!",        // Vietnamese
  "Пролетарі всіх країн, єднайтеся!",            // Ukrainian
  "Пралетарыі ўсіх краін, яднайцеся!",           // Belarusian
  "Пролетарии от всички страни, съединявайте се!", // Bulgarian
  "Пролетери од сите земји, обединете се!",      // Macedonian
  "বিশ্বের শ্রমিকরা, এক হও!",                      // Bengali
  "دنیا کے محنت کشو، ایک ہو جاؤ!",               // Urdu
  "உலகத் தொழிலாளர்களே, ஒன்றுபடுங்கள்!",          // Tamil
  "ప్రపంచ కార్మికులారా, ఏకం కాండి!",             // Telugu
  "ലോക തൊഴിലാളികളേ, സംഘടിക്കുവിൻ!",              // Malayalam
  "ವಿಶ್ವದ ಕಾರ್ಮಿಕರೇ, ಒಂದಾಗಿ!",                   // Kannada
  "जगातील कामगारांनो, एक व्हा!",                 // Marathi
  "દુનિયાના મજૂરો, એક થાઓ!",                     // Gujarati
  "ਸੰਸਾਰ ਦੇ ਮਜ਼ਦੂਰੋ, ਇੱਕ ਹੋ ਜਾਓ!",                // Punjabi
  "ලෝකවාසී කම්කරුවෙනි, එක්වෙන්න!",               // Sinhala
  "ผู้ใช้แรงงานทั่วโลก จงสามัคคีกัน!",            // Thai
  "Kaum buruh di seluruh dunia, bersatulah!",     // Indonesian / Malay
  "Mga manggagawa ng daigdig, magkaisa!",        // Tagalog / Filipino
  "អ្នកធ្វើការទូទាំងពិភពលោក អើយ ចូររួបរួមគ្នា!",       // Khmer
  "ຜູ້ອອກແຮງງານທົ່ວໂລກ, ຈົ່ງໂຮມກັນ!",            // Lao
  "ကမ္ဘာ့အလုပ်သမားများ၊ စည်းလုံးကြပါ!",           // Burmese
  "Bütün ülkelerin işçileri, birleşin!",         // Turkish
  "Bütün ölkələrin proletarları, birləşin!",     // Azerbaijani
  "Բոլոր երկրների պրոլետարներ, միացե՛ք",          // Armenian
  "Proletariusze wszystkich krajów, łączcie się!", // Polish
  "Proletáři všech zemí, spojte se!",            // Czech
  "Világ proletárjai, egyesüljetek!",            // Hungarian
  "Proletari din toate țările, uniți-vă!",        // Romanian
  "Arbejdere i alle lande, foren jer!",          // Danish
  "Kaikkien maiden proletaarit, liittykää yhteen!", // Finnish
  "Kõigi maade proletaarlased, ühinege!",        // Estonian
  "Visu zemju proletārieši, savienojieties!",    // Latvian
  "Visų šalių meilės darbininkai, vienykitės!",  // Lithuanian
  "Oibrithe an domhain, téigí i dtร่วม!",         // Irish
  "Gweithwyr yr holl diroedd, unwch!",           // Welsh
  "Luchd-obrach an t-saoghail, aonaibh!",        // Scottish Gaelic
  "Munduko langileak, elkartu zaitezte!",        // Basque
  "Proletaris de tots els països, uniu-vos!",    // Catalan
  "Trabalhadores de todos os países, unídevos!", // Galician
  "Ħaddiema tal-dinja, ingħaqdu!",               // Maltese
  "Proletarë të të gjitha vendeve, bashkohuni!", // Albanian
  "Aarbechter aller Länner, vereenegt Iech!",    // Luxembourgish
  "Öreigar katoch landa, þjappið ykkur saman!", // Icelandic
  "Wafanyakazi wa dunia, unganeni!",             // Swahili
  "Ndị ọrụ nke ụwa, jikọta ọnụ!",                // Igbo
  "Eyin osise gbogbo agbaye, e darapo!",          // Yoruba
  "Ma'aikatan dukkan kasashe, ku haɗu!",         // Hausa
  "Vashandi vepasi rese, kubatanai!",            // Shona
  "Tāngata mahi o te ao, whakakotahi!",          // Maori
  "E ka poʻe hana o ka honua, e hui pū!",         // Hawaiian
  "Барлық елдердің пролетарлары, бірігіңдер!",    // Kazakh
  "Бардык өлкөлөрдүн пролетарлары, бириккиле!",   // Kyrgyz
  "Пролетарҳои ҳамаи мамлакатҳо, як шавед!",      // Tajik
  "Дэлхийн пролетари нар нэгдэгтүн!",             // Mongolian
  "Barcha mamlakatlar proletarlari, birlashingiz!", // Uzbek
  "Ähli ýurtlaryň proletarlary, birleşiň!",       // Turkmen
  "کارگران جهان، متحد شوید!",                    // Persian / Farsi
  "د نړۍ کارګرانو، متحد شئ!",                     // Pashto
  "کرکِران جهان، متحد شو!",                       // Balochi
  "دنیا جا مزدورو، هڪ ٿيو!",                      // Sindhi
  "Bijî karkerên cîhanê, yek bibin!",            // Kurdish (Kurmanji)
  "کرێکارانی جیهان، یەکبگرن!",                   // Kurdish (Sorani)
  "འཛམ་གླིང་གི་ངལ་རྩོལ་ပ། མཉམ་སྦྲེལ་བྱེད།",     // Tibetan
  "دۇنيادىكى ئەمگەكچىلەر، بىرلەشىڭلار!",        // Uyghur
  "Proletarii ex omnibus terris, unimini!",      // Latin
  "Proletari de tute la landi, unijez!",         // Ido
  "Proletarioj de chiuj landoj, unuighu!",        // Esperanto
  "Kaum buruh ti sakuliah dunya, ngahiji!",      // Sundanese
  "Pekerja makasami ring dunia, ngiring masikian!", // Balinese
  "বিশ্বৰ সকলো দেশৰ শ্ৰমিকসকল, এক হওঁক!",        // Assamese
  "සර්වදෙශීය කම්කරුවනි, එක්වෙන්න!",             // Sinhala (Formal Marxist slogan)
  "Kabuki-an ta manga taw a peg-galbek, pakasakata!", // Maranao
  "Manggagawa sa buong mundo, magkaisa!",        // Cebuano / Bisaya
  "Poyetè di tot l' monde, unissîs-vos!",        // Walloon
  "Treballadors de tot el món, uniu-vos!",        // Valencian
  "Langile guztiak, elkartu zaitezte!",          // Basque (Variant)
  "Arbeiderne i alle land, foren dere!",          // Norwegian (Bokmål)
  "Arbeidarar i alle land, samla dykk!",         // Norwegian (Nynorsk)
  "Asebenzi bomhlaba, hlangananani!",             // Zulu / Xhosa
  "Bašomi ba lefase, kopanang!",                 // Northern Sotho
  "Bodiri ba lefatshe, kopanang!",                // Tswana
  "የዓለም ሠራተኞች፣ ተባበሩ!",                    // Amharic
  "Shaqaalaha dunida, unooba!",                  // Somali
  "Abakozi b'isi yose, nimwimunye!",              // Kinyarwanda
  "Mpitso-draharaha amin'izao tontolo izao, mampiray!", // Malagasy
  "Oibrithe an domhain, aontaígí!",               // Irish (Modern spelling)
  "Gweithwyr y byd, unowch!",                    // Welsh (Variant)
  "Kaimahi o te ao, whakakotahi!",               // Maori (Alternative)
];

const longLiveChairmanMaoMessages = [
  "Long live Chairman Mao!",                      // English
  "¡Viva el Presidente Mao!",                   // Spanish
  "Leve voorzitter Mao!",                        // Dutch
  "Es lebe Vorsitzender Mao!",                  // German
  "Longue vie au président Mao !",             // French
  "Länge leve ordförande Mao!",                // Swedish
  "毛主席万岁！",                                 // Chinese (Simplified)
  "마오 주석 만세!",                              // Korean
  "毛主席萬歲！",                                 // Chinese (Traditional / Cantonese)
  "Да здравствует председатель Мао!",            // Russian
  "تحيا الرئيس ماو!",                            // Arabic
  "Viva o Presidente Mao!",                    // Portuguese
  "Živio predsjednik Mao!",                    // Croatian
  "Nech žije předseda Mao!",                   // Czech
  "長壽毛主席！",                                // Taiwanese (Literate phrase)
  "चेयरमैन माओ ज़िंदाबाद!",                     // Hindi
  "毛主席万歳！",                                 // Japanese
  "Niech żyje Przewodniczący Mao!",             // Polish
  "Éljen Mao elnök!",                          // Hungarian
  "Trăiască Președintele Mao!",                 // Romanian
  "Længe leve Formand Mao!",                   // Danish
  "Lenge leve Formann Mao!",                   // Norwegian
  "Eläköön puheenjohtaja Mao!",                // Finnish
  "Elagu esimees Mao!",                        // Estonian
  "Lai dzīvo priekšsēdētājs Mao!",             // Latvian
  "Tegyvuoja Pirmininkas Mao!",                // Lithuanian
  "Go mairfidh an Cathaoirleach Mao!",         // Irish
  "Hir oes i gadeirydd Mao!",                   // Welsh
  "Bivat o Presidente Mao!",                   // Galician
  "Gora Mao Lehendakaria!",                    // Basque
  "Visca el President Mao!",                   // Catalan
  "Viva il Presidente Mao!",                   // Italian
  "Zito o Proedros Mao!",                       // Greek (Ζήτω ο Πρόεδρος Μάο!)
  "Да живее председателят Мао!",              // Bulgarian
  "Хай живе голова Мао!",                      // Ukrainian
  "Няхай жыве старшыня Мао!",                  // Belarusian
  "Živeo predsednik Mao!",                     // Serbian / Bosnian
  "Да живее претседателот Мао!",               // Macedonian
  "Nech žije predseda Mao!",                   // Slovak
  "Rrofftë Kryetari Mao!",                     // Albanian
  "Lifa Formaður Mao!",                        // Icelandic
  "মাও চেয়ারম্যান জিন্দাবাদ!",                  // Bengali
  "چیئرمین ماؤ زندہ باد!",                       // Urdu
  "தலைவர் மாஓ வாழ்க!",                         // Tamil
  "ఛైర్మన్ మావో వర్ధిల్లాలి!",                   // Telugu
  "ചെയർമാൻ മാവോ ദീർഘായുസ്സായിരിക്കട്ടെ!",       // Malayalam
  "ಚೇರ್ಮನ್ ಮಾವೋ ದೀರ್ಘಾಯುವಾಗಲಿ!",               // Kannada
  "चेअरमन माओ जिंदाबाद!",                      // Marathi
  "ચેરમેન માઓ ઝિંદાબાદ!",                      // Gujarati
  "ਚੇਅਰਮੈਨ ਮਾਓ ਜ਼ਿੰਦਾਬਾਦ!",                     // Punjabi
  "මාඕ සභාපතිතුමාට දීර්ඝායු වේවා!",           // Sinhala
  "ประธานเหมา จงเจริญ!",                        // Thai
  "Hiduplah Ketua Mao!",                        // Indonesian / Malay
  "Mabuhay si Tagapulong Mao!",                // Filipino / Tagalog
  "ប្រធានម៉ៅ ចំរើនអាយុยืน!",                      // Khmer
  "ປະທານ ເໝົາ ຈົ່ງຈະເລີນ!",                     // Lao
  "ဥက္ကဋ္ဌမော် ရာဇဝင်ရှည်ပါစေ!",                 // Burmese
  "Mao Predsedatel xush kelsin!",               // Uzbek (Мао раис яшасин!)
  "Мао төраға жасасын!",                       // Kazakh
  "Төрага Мао жашасын!",                        // Kyrgyz
  "Раиси Мао зинда бод!",                      // Tajik
  "Мао дарга мандтугай!",                      // Mongolian
  "چیئرمین ماؤ زندہ باد!",                       // Pashto
  "رئیس مائو زنده باد!",                        // Persian / Farsi
  "Yaşasın Başkan Mao!",                       // Turkish
  "Bijî Serok Mao!",                           // Kurdish (Kurmanji)
  "بژێت سەرۆک ماۆ!",                           // Kurdish (Sorani)
  "Chairman Mao Tashi Delek!",                 // Tibetan (毛主席万岁 / མའོ་ကျུའུ་ཞིས་ཁྲི་ལོ་བརྟན་པར་ཤོག།)
  "Рәйис Мао яшисун!",                         // Uyghur
  "Mwenyekiti Mao Aishi Maisha Marefu!",       // Swahili
  "K'ade pe fun Alaga Mao!",                   // Yoruba
  "Onye isi oche Mao dọrọ ndụ!",               // Igbo
  "Shugaba Mao Ya Rayu!",                      // Hausa
  "Mwenyekiti Mao vive!",                      // Lingala
  "ሊቀመንበር ማኦ ይኖሩ!",                        // Amharic
  "Guddoomiye Mao Ha Noolaado!",                // Somali
  "Kia ora te Tiamana Mao!",                   // Maori
  "E ola ka Luna Mao!",                        // Hawaiian
  "Kida na Tiamani Mao!",                      // Fijian
  "¡Viva el Presidente Mao!",                  // Quechua / Aymara (Borrowed)
  "Chairman Mao Tunngasugit!",                 // Inuktitut
  "Longfala laef long Tsiaman Mao!"             // Bislama
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
  const isSovietUnionFoundingDay = currentMonth === 11 && currentDay === 30; // Dec 30
  const isMaoBirthday = currentMonth === 11 && currentDay === 26; // Dec 26
  const isChristmasSeason = !isSovietUnionFoundingDay && !isMaoBirthday && (currentMonth === 11 || currentMonth === 0);

  // Fade out
  welcomeText.classList.add("fade-out");

  setTimeout(() => {
    if (isSovietUnionFoundingDay) {
      welcomeText.textContent = workersOfTheWorldUniteMessages[currentMessageIndex];
      currentMessageIndex = (currentMessageIndex + 1) % workersOfTheWorldUniteMessages.length;
    } else if (isMaoBirthday) {
      // Cycle through "Long live Chairman Mao!" messages in different languages
      welcomeText.textContent = longLiveChairmanMaoMessages[currentMessageIndex % longLiveChairmanMaoMessages.length];
      currentMessageIndex = (currentMessageIndex + 1) % longLiveChairmanMaoMessages.length;
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
