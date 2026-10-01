/**
 * Shared Prettier configuration.
 * Referenced from the root package.json `prettier` field.
 */
module.exports = {
  singleQuote: true,
  semi: true,
  trailingComma: 'all',
  printWidth: 100,
  tabWidth: 2,
  arrowParens: 'always',
  endOfLine: 'lf',
  overrides: [
    {
      files: ['*.prisma'],
      options: { printWidth: 120 },
    },
  ],
};
