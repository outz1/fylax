import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    setupFiles: ['./src/test-setup.ts'],
    // Os testes de integração compartilham o mesmo Postgres.
    fileParallelism: false,
  },
});
