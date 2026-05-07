module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }
  try {
    const { model, messages, system, max_tokens } = req.body;
    
    // Convertir formato Anthropic a Gemini
    const contents = messages.map(m => ({
      role: m.role === 'assistant' ? 'model' : 'user',
      parts: Array.isArray(m.content) 
        ? m.content.map(c => {
            if (c.type === 'text') return { text: c.text };
            if (c.type === 'image') return { inline_data: { mime_type: c.source.media_type, data: c.source.data }};
            if (c.type === 'document') return { inline_data: { mime_type: 'application/pdf', data: c.source.data }};
            return { text: '' };
          })
        : [{ text: m.content }]
    }));

    if (system) contents.unshift({ role: 'user', parts: [{ text: system }] });

    const apiKey = process.env.GEMINI_API_KEY;
    const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;
    
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ contents, generationConfig: { maxOutputTokens: max_tokens || 1500 } })
    });

    const data = await response.json();
    if (!response.ok) return res.status(response.status).json(data);
    
    const text = data.candidates?.[0]?.content?.parts?.[0]?.text || '{}';
    return res.status(200).json({ content: [{ type: 'text', text }] });

  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
};
