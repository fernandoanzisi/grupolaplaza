const { createClient } = require('@supabase/supabase-js');
 
const supabaseAdmin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);
 
module.exports = async function handler(req, res) {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
 
  // Solo POST
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }
 
  try {
    // Verificar token del admin
    const authHeader = req.headers.authorization || '';
    const token = authHeader.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'No autorizado' });
 
    const { data: { user }, error: authError } = await supabaseAdmin.auth.getUser(token);
    if (authError || !user) return res.status(401).json({ error: 'Token inválido' });
 
    // Verificar que es admin
    const { data: perfil } = await supabaseAdmin
      .from('perfiles')
      .select('rol')
      .eq('id', user.id)
      .single();
 
    if (!perfil || perfil.rol !== 'admin') {
      return res.status(403).json({ error: 'Solo el administrador puede crear usuarios' });
    }
 
    // Datos del nuevo usuario
    const { nombre, email, password, rol, rubros } = req.body;
    if (!nombre || !email || !password) {
      return res.status(400).json({ error: 'Faltan datos: nombre, email, password' });
    }
 
    // Crear usuario en Supabase Auth
    const { data: newUser, error: createError } = await supabaseAdmin.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: { nombre, rol: rol || 'usuario' }
    });
 
    if (createError) return res.status(400).json({ error: createError.message });
 
    // Crear perfil
    await supabaseAdmin.from('perfiles').upsert({
      id: newUser.user.id,
      nombre,
      email,
      rol: rol || 'usuario',
      rubros: rubros || [],
      creado_por: user.id,
    }, { onConflict: 'id' });
 
    return res.status(200).json({ ok: true, userId: newUser.user.id });
 
  } catch(e) {
    return res.status(500).json({ error: e.message });
  }
};
 
