import english from './locales/en.json';
import spanish from './locales/es.json';

export type Language = 'en' | 'es';
export type TranslationKey = keyof typeof english;

const translations: Record<Language, Record<TranslationKey, string>> = {
  en: english,
  es: spanish,
};

export function translate(language: Language, key: TranslationKey, values: Record<string, string> = {}): string {
  return translations[language][key].replace(/\{(\w+)\}/g, (_, name: string) => values[name] ?? `{${name}}`);
}
