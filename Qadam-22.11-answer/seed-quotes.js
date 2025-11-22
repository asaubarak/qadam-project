import 'dotenv/config';
import pg from 'pg';

const client = new pg.Client({
  connectionString: process.env.DATABASE_URL,
});

const sampleQuotes = [
  // Октябрь (месяц 10)
  { text: "Білім - өмір бақытының кілті", author: "Абай Құнанбаев", month: 10 },
  { text: "Оқу - көзсіз адамға таяқ, білімсіз адамға жол", author: "Қазақ мақалы", month: 10 },
  { text: "Ғылым үйренбек керек, ғылымсыз білім жоқ", author: "Абай Құнанбаев", month: 10 },
  { text: "Өз халқының намысын өзі қорғайтын ұрпақ керек", author: "Мұхтар Әуезов", month: 10 },
  { text: "Еңбек етсең ерінбей, тояды қарның тіленбей", author: "Қазақ мақалы", month: 10 },
  
  // Ноябрь (месяц 11)
  { text: "Адал еңбек адамды асқақтатады", author: "Қазақ мақалы", month: 11 },
  { text: "Білімді мықты ұстаған адам бақытқа жетеді", author: "Әл-Фараби", month: 11 },
  { text: "Ұстазыңды құрметте, білімді бағала", author: "Қазақ мақалы", month: 11 },
];

async function seedQuotes() {
  try {
    await client.connect();
    console.log('📦 Connected to database');
    
    for (const quote of sampleQuotes) {
      await client.query(
        'INSERT INTO quotes (text, author, month, "order") VALUES ($1, $2, $3, 0)',
        [quote.text, quote.author, quote.month]
      );
    }
    
    console.log(`✅ Added ${sampleQuotes.length} sample quotes`);
    console.log('📊 Quotes distribution:');
    console.log('   - Октябрь: 5 цитат');
    console.log('   - Ноябрь: 3 цитаты');
  } catch (error) {
    console.error('❌ Error seeding quotes:', error);
    process.exit(1);
  } finally {
    await client.end();
  }
}

seedQuotes();
