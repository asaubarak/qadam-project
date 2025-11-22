import pg from 'pg';
const { Client } = pg;

async function makeAdmin() {
  const client = new Client({
    connectionString: process.env.DATABASE_URL,
  });

  try {
    await client.connect();
    console.log('✅ Connected to database');

    const result = await client.query(
      `UPDATE users SET role = 'admin' WHERE username = $1 RETURNING id, username, role`,
      ['Kanat']
    );

    if (result.rows.length > 0) {
      console.log('✅ User updated to admin:', result.rows[0]);
    } else {
      console.log('❌ User not found');
    }

  } catch (error) {
    console.error('❌ Error:', error);
  } finally {
    await client.end();
  }
}

makeAdmin();
