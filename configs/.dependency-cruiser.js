/** @type {import('dependency-cruiser').IConfiguration} */
module.exports = {
  forbidden: [
    {
      name: 'no-client-import-db',
      comment: 'Client components cannot directly import database drivers or database connection pools',
      severity: 'error',
      from: {
        path: '^src/components/.*'
      },
      to: {
        path: '(/pg/|^pg$|^pg/|/lib/.*db|/db/|@prisma/client|drizzle-orm|typeorm|mysql2|mongodb)'
      }
    },
    {
      name: 'no-client-import-server-only',
      comment: 'Client components cannot import server-only modules',
      severity: 'error',
      from: {
        path: '^src/components/.*'
      },
      to: {
        path: '^src/lib/server/.*'
      }
    }
  ],
  options: {
    tsPreCompilationDeps: true,
    enhancedResolveOptions: {
      exportsFields: ['exports'],
      conditionNames: ['import', 'require', 'node', 'default']
    }
  }
};
