// Gabarit : remplacer railway-setup-check. Sert site/ sous https://theaipipe.com/demos/railway-setup-check/ (static files only).
// The route is more specific than the galerie-presell route theaipipe.com/demos/*, so it wins.
const BASE = '/demos/railway-setup-check';
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === BASE) return Response.redirect(`${url.origin}${BASE}/`, 308);
    if (!url.pathname.startsWith(BASE + '/')) return new Response('Not found', { status: 404 });
    const path = url.pathname.slice(BASE.length) || '/';
    const res = await env.ASSETS.fetch(new Request(new URL(path, url.origin), request));
    const out = new Response(res.body, res);
    const loc = out.headers.get('Location');
    if (loc && loc.startsWith('/')) out.headers.set('Location', BASE + loc);
    out.headers.set('X-Robots-Tag', 'noindex, nofollow');
    return out;
  },
};
