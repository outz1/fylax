/**
 * URL segura para log: mantém origem e caminho, mantém só os NOMES dos parâmetros de query
 * (os valores podem ser token ou segredo) e descarta credenciais e fragmento.
 */
export function redactUrl(input: string): string {
  try {
    const u = new URL(input);
    const keys = [...new Set(u.searchParams.keys())];
    const query = keys.length > 0 ? `?${keys.map((k) => `${k}=…`).join('&')}` : '';
    return `${u.protocol}//${u.host}${u.pathname}${query}`;
  } catch {
    return '(url inválida)';
  }
}
