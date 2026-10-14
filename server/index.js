import { createApp } from './src/app.js';
const need = ['SUPABASE_URL','SUPABASE_PUBLISHABLE_KEY'].filter(k => !process.env[k]);
if (need.length) console.warn('Missing', need.join(', '), '- sign-in dependent routes will return 401 until set in the environment.');
const port = process.env.PORT || 8787; createApp().listen(port, () => console.log('Sentrix API on port', port));
