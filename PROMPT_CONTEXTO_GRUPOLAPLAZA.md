# CONTEXTO COMPLETO — GRUPO LA PLAZA
## Prompt para continuar en Claude Code

---

## ¿QUÉ ES ESTE PROYECTO?

Estoy desarrollando una **plataforma financiera web a medida** para el Grupo La Plaza, empresa del sector combustibles/agro/logística en la Patagonia argentina (Neuquén/Río Negro). La app está **en producción** y la uso diariamente.

**URL en producción:** https://grupolaplaza.vercel.app  
**Repositorio GitHub:** https://github.com/fernandoanzisi/grupolaplaza  
**Rama principal:** `main`

---

## STACK TÉCNICO

| Componente | Tecnología | Detalle |
|---|---|---|
| Frontend | HTML + CSS + JS puro | Un solo archivo `index.html` (~17.200 líneas) |
| Deploy | Vercel | Auto-deploy al hacer push a `main` en GitHub |
| Base de datos | Supabase (PostgreSQL) | URL: `https://udneubfilwyufurzbgie.supabase.co` |
| IA documentos | Google Gemini API | Key en Vercel como `GEMINI_API_KEY` |
| Proxy API | `/api/claude.js` en Vercel | Carpeta `api/` en el repo |
| Auth | Supabase Auth (email/password) | |
| Excel | SheetJS (XLSX) | CDN, para importar planillas |

---

## ARQUITECTURA DEL ARCHIVO PRINCIPAL

El archivo `index.html` es **monolítico** — todo el CSS, HTML y JS en un solo archivo. Estructura:

```
<head> — estilos CSS globales + variables
<nav> — barra de navegación superior con menús desplegables
<div class="main"> — contenedor de todas las páginas
  <div class="page active" id="page-dashboard"> — página activa por defecto
  <div class="page" id="page-cheques">
  <div class="page" id="page-riesgo">
  <div class="page" id="page-gastos">        ← NUEVO
  <div class="page" id="page-lector_doc">    ← NUEVO
  <div class="page" id="page-guardia">
</div><!-- /main -->
<!-- MODALS -->
<script> — bloque JS principal (~312.000 chars)
<script> — módulos adicionales (extractos, cartera, etc.)
... más bloques script
<script> — chequesHistorial (NUEVO)
<script> — lectorDocumentos (NUEVO)
<script> — gastosAnalisis (NUEVO)
</body>
</html>
```

**CRÍTICO:** Todas las `<div class="page">` DEBEN estar dentro de `<div class="main">` antes de `</div><!-- /main -->`. Si quedan fuera, la página no se muestra o se mezcla con otras secciones.

### Sistema de navegación
```javascript
// navGo(pageId, triggerEl) — oculta todas las páginas y muestra la pedida
// Dispatch table en función navGo (~línea 8884):
'gastos':       ()=>gastosRender(),
'lector_doc':   ()=>lectorRender(),
'pasivos':      ()=>pasivosRender(),
// etc.
```

### CSS de páginas
```css
.page { display: none; }
.page.active { display: block; }
```

---

## SUPABASE — TABLAS Y ESTRUCTURA

### Tablas existentes
| Tabla | Contenido | RLS |
|---|---|---|
| `app_state` | Estado principal (empresas, cfFilas, etc.) | SELECT + ALL para authenticated |
| `app_cache` | Cache de módulos (rechazados, obras, pasivos, gastos, etc.) | SELECT + ALL para authenticated |
| `extracto_bancario` | 91.500+ movimientos bancarios | SELECT + ALL para authenticated |
| `cartera_debo` | Cheques de cartera (cartDebo) | SELECT + ALL para authenticated |
| `flujo_de_efectivo_filas` | Filas del cash flow | SELECT + ALL para authenticated |
| `clientes_debo` | Clientes de cartera | SELECT + ALL para authenticated |
| `perfiles` | Usuarios: nombre, rol, rubros | DELETE + SELECT + UPDATE + INSERT |

### Usuario admin principal
- **Email:** anzisifernando@gmail.com
- **User ID:** `1da12809-0a1c-4057-887c-0c32dcebdd73`
- **Rol:** admin

### Sistema de cache
Los datos que no son cheques ni extractos se guardan en `app_cache` con esta estructura:
```javascript
// Guardar
cacheGuardar('gastos', arrayDeDatos);  // guarda en app_cache con user_id del admin

// Al cargar (cacheCargarTodo), busca siempre con el ADMIN_ID fijo:
const ADMIN_ID = '1da12809-0a1c-4057-887c-0c32dcebdd73';
// para que todos los usuarios vean los mismos datos
```

Claves en app_cache: `obras`, `minuta`, `preoperatorio`, `petroleras`, `pnl`, `flota`, `riesgo`, `fci`, `Datos lc`, `petroData`, `nlp`, `tarjetas`, `rechazados`, `pasivos`, `gastos`, `Galicia`

---

## MÓDULOS Y PÁGINAS DE LA APP

### Menú principal
- **Dashboard** — KPIs consolidados del grupo
- **Dinero** → Bancos, Efectivo, Extractos, Cash Flow, FCI, Mercados
- **Empresas** → RS (Rio Salado), SC (Servicios Cipolletti), LP (La Plaza)
- **Gestión** → Cheques, Rechazados, Cartera de Valores, NLP Comisiones, Pasivos Financieros, **Análisis de Gastos** *(nuevo)*, Obras, Riesgo Crediticio, Tarjetas, Flota, Petroleo
- **Excel** → Importación de todos los Excel
- **🔍 Lector de Documentos** *(nuevo)*

### Páginas nuevas agregadas en esta sesión

#### 1. Análisis de Gastos (`page-gastos`)
- Importación desde sección Excel (hoja BASE/Hoja1 del Excel contable)
- Columnas: Descripción, Cuenta (contable), Debe, Haber, Saldo, Unidad de negocio, Mes
- 14 Unidades de negocio: BASE ROCA, CASA CENTRAL, LP, RS, RS CHICHINALES, SC, SC CINCO SALTOS, etc.
- 166 cuentas contables, 1.490 registros (Ene-Abr 2026)
- KPIs: Total Debe, Total Haber, Saldo neto, cant. UUNN, cant. cuentas
- Filtros: mes, UUNN, cuenta, tipo, búsqueda libre
- Gráficos de barras: top cuentas por debe + debe por UUNN
- Guardado en Supabase via `cacheGuardar('gastos', datos)`
- **Pendiente:** al importar el Excel de gastos, también dispara el parser de Riesgo Crediticio. Hay que separar los parsers.

#### 2. Lector de Documentos (`page-lector_doc`)
- Acepta: PDF, JPG/PNG, Excel/XLSX, CSV
- Llama a `/api/claude` (proxy en Vercel) que usa Google Gemini 2.0 Flash
- Extrae: categoría, ente, empresa, período, vencimiento, importe, campos detallados, movimientos
- Historial guardado en `localStorage` con key `lector_docs_v1`
- **Estado actual:** la API de Gemini da error 429 (cuota excedida por exceso de pruebas). Se resetea en 24-48hs.

---

## FUNCIONALIDADES NUEVAS IMPLEMENTADAS

### A. Historial de cartera de cheques
```javascript
function chequesHistorialGuardar()  // se llama al importar Excel de cartera
function chequesHistorialRender()   // renderiza tabla de snapshots
// Storage: localStorage 'chq_historial_v1'
// Botón: 📜 Historial (junto a "+ Nuevo cheque")
// Panel: id="chq-historial-wrap" (toggle show/hide)
```

### B. Sistema de amortización en Pasivos
```javascript
function pasivosRecalcAmort()  // calcula cuota/saldo según sistema
// Selector: id="pas-sistema" (frances/aleman/plano)
// Campos auxiliares: pas-amort-capital, pas-amort-tna, pas-amort-plazo, pas-amort-pagadas
// Resultado: se copia a campos existentes pas-capital, pas-saldo, pas-cuota, pas-tna, pas-cuotas-pend
```

### C. Fix Top 5 clientes cheques
```javascript
// Solo cuenta cheques con estado 'EN CARTERA' activa
// Excluye hojas históricas Dep.GALICIA que contaminaban el resultado
filtered.filter(c=>(c.estadoActual||c.estado||'').toUpperCase()==='EN CARTERA')
```

### D. Spinner de carga
```javascript
// En onLogin(), antes era: renderDashboard() inmediato (pantalla negra)
// Ahora: muestra spinner girando → loadFromSupabase() → renderDashboard()
// Evita pantalla en negro mientras Supabase carga los datos
```

---

## ARCHIVO /api/claude.js (proxy Vercel)

```javascript
// Ubicación: /api/claude.js en el repo GitHub
// Convierte formato Anthropic → Gemini y llama a Google Gemini 2.0 Flash
module.exports = async function handler(req, res) {
  // ...convierte messages de formato Anthropic a Gemini...
  const apiKey = process.env.GEMINI_API_KEY;
  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;
  // ...
};
```

**Variables de entorno en Vercel:**
- `GEMINI_API_KEY` — Google AI Studio key (actualmente bloqueada por 429, proyecto: `gen-lang-client-0204189638`)
- `ANTHROPIC_API_KEY` — Anthropic key (tiene créditos pero requiere pago $5 mínimo)
- `SUPABASE_URL` — URL del proyecto Supabase
- `CLAVE_DE_SERVICIO_SUPABASE` — service role key

---

## CÓMO TRABAJAMOS — REGLAS IMPORTANTES

### Workflow para modificar index.html
1. Siempre trabajar sobre el `index.html` que te paso (el más reciente)
2. Hacer backup antes de tocar: `cp index.html index_backup.html`
3. Usar Python para str_replace y evitar problemas de encoding
4. Verificar integridad con checklist antes de entregar:
   - Scripts balanceados (mismo número de `<script>` y `</script>`)
   - Cierre HTML correcto (`</html>` al final)
   - Funciones clave presentes: `chequesHistorialGuardar`, `pasivosRecalcAmort`, `lectorRender`, `gastosRender`, `renderCheques`, `pasivosRender`
   - Páginas nuevas DENTRO de `<div class="main">` antes de `</div><!-- /main -->`

### Principio fundamental
**"NO ROMPER NADA"** — cada cambio es solo aditivo. Nunca modificar funcionalidad existente, solo agregar. Siempre mostrar preview visual antes de tocar el código.

### Para agregar una sección nueva
1. Agregar nav item en el menú (después de un item existente)
2. Agregar dispatch en `navGo` dispatch table
3. Agregar `<div class="page" id="page-NOMBRE">` DENTRO de `<div class="main">` antes de `</div><!-- /main -->`
4. Agregar funciones JS en un `<script>` nuevo al final antes de `</body>`
5. Si tiene importación Excel, agregarla en la página Excel (no en el panel)
6. Si tiene datos persistentes, usar `cacheGuardar('clave', datos)` para Supabase

---

## PENDIENTES / PRÓXIMOS PASOS

1. **Lector de Documentos** — esperar que se resetee el límite 429 de Gemini (24-48hs desde 08/05/2026). Luego probar con un PDF real.

2. **Análisis de Gastos** — al importar el Excel de gastos, también dispara el parser de Riesgo Crediticio. Hay que separar el trigger de importación para que solo procese la hoja BASE/Hoja1 y no toque Riesgo.

3. **Permisos por rubro de usuario** — los rubros (Administración, Finanzas, Operaciones, etc.) están guardados en `perfiles` pero no restringen las secciones visibles todavía. Hay que conectar: si el usuario tiene rubro "Finanzas" → ve Cheques, Pasivos, Extractos. Si tiene "Operaciones" → ve Combustibles, Flota, Obras.

4. **Cambio de contraseña** — los usuarios no tienen forma de cambiar su propia contraseña desde la app. Hay que agregar un botón en el menú de perfil que use `supa.auth.updateUser({ password: nuevaPass })`.

5. **Dashboard por empresa** — vista individual con KPIs propios para RS, SC y LP.

6. **Crear usuario — error 500** — el archivo `api/create-user.js` a veces falla con 500. Revisar logs en Vercel → Registros para ver el error exacto. El `package.json` ya fue agregado a la carpeta `api/`.

---

## DATOS DEL NEGOCIO

- **Grupo La Plaza** — estaciones de servicio YPF + agro + logística
- **3 empresas:** Rio Salado SRL (RS), Servicios Cipolletti SRL (SC), La Plaza SA (LP)
- **14 Unidades de negocio:** BASE ROCA, CASA CENTRAL, RS, RS CHICHINALES, RS CTRO VR, RS ROCA, RS RUTA VR, SC, SC CINCO SALTOS, SC ESMERALDA, SC PACHECO, LP, PAL CHOELE
- **Ubicación:** Neuquén / Río Negro, Argentina
- **Moneda:** Pesos argentinos (ARS), algunos datos en USD

---

## RESUMEN DE LO QUE FUNCIONA HOY

✅ Login con Supabase Auth  
✅ Datos sincronizados en la nube (91.500 movimientos extractos, 1.444 cheques, pasivos, obras, rechazados, tarjetas, etc.)  
✅ Multi-usuario con roles Admin/Usuario  
✅ Importación de Excel (cartera, extractos, gastos, etc.)  
✅ Historial de cartera de cheques con snapshots diarios  
✅ Pasivos financieros con sistema de amortización (Francés/Alemán/Plano)  
✅ Análisis de Gastos contable (14 UUNN, 166 cuentas)  
✅ Lector de Documentos (panel listo, API pendiente de reseteo)  
✅ Spinner de carga al entrar (evita pantalla negra)  
✅ Top 5 clientes limpio (solo cartera activa)  

---

*Última actualización: Mayo 2026 — generado desde sesión de trabajo con Claude*
