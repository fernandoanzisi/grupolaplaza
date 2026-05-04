import { createClient } from '@supabase/supabase-js';
 
const supabaseAdmin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);
 
export default async function handler(req, res) {
  // Solo POST
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }
 
  // Verificar que el que llama es admin
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No autorizado' });
 
  const token = authHeader.replace('Bearer ', '');
  const { data: { user }, error: authError } = await supabaseAdmin.auth.getUser(token);
  if (authError || !user) return res.status(401).json({ error: 'Token inválido' });
 
  // Verificar rol admin en perfiles
  const { data: perfil } = await supabaseAdmin
    .from('perfiles')
    .select('rol')
    .eq('id', user.id)
    .single();
 
  if (!perfil || perfil.rol !== 'admin') {
    return res.status(403).json({ error: 'Solo el administrador puede crear usuarios' });
  }
 
  // Crear el usuario nuevo
  const { nombre, email, password, rol, rubros } = req.body;
  if (!nombre || !email || !password) {
    return res.status(400).json({ error: 'Faltan datos: nombre, email, password' });
  }
 
  const { data: newUser, error: createError } = await supabaseAdmin.auth.admin.createUser({
    email,
    password,
    email_confirm: true,
    user_metadata: { nombre, rol: rol || 'usuario' }
  });
 
  if (createError) return res.status(400).json({ error: createError.message });
 
  // Crear perfil en tabla perfiles
  await supabaseAdmin.from('perfiles').upsert({
    id: newUser.user.id,
    nombre,
    email,
    rol: rol || 'usuario',
    rubros: rubros || [],
    creado_por: user.id,
    creado_at: new Date().toISOString()
  }, { onConflict: 'id' });
 
  return res.status(200).json({ ok: true, userId: newUser.user.id });
}
