var webpackConfig = require('./webpack.config');

module.exports = function(config) { 
  config.set({

      frameworks: ["jasmine"],

      files: [
        { pattern: "tests/**/*spec.browser.ts" , served: true, watched: true},
        { pattern: "lib//index.ts", served: false, included:false },
        { pattern: "lib/**/*.ts", served: true, watched: true },
        //{ pattern: "tests/DidKey.spec.browser.js", included: true, watched: true }
      ],

      "exclude": [
        "lib/**/*.d.ts",
        "/node_modules/**/index.d.ts"
    ],

      preprocessors: {
        "tests/**/*.ts": ["webpack"],
        "lib/**/*.ts": ["webpack"]
    },
    webpack: {
      module: webpackConfig.module,
      resolve: webpackConfig.resolve
    },
    reporters: ['progress'],
    port: 9876,
    colors: true,
    logLevel: config.LOG_INFO,
    autoWatch: true,
    browsers: ['ChromeHeadless'],
    singleRun: false,
    concurrency: Infinity,      
    customLaunchers: {
        Chrome_with_debugging: {
        base: 'Chrome',
        flags: ['--remote-debugging-port=9222'],
        debug: true
        }
      },

    logLevel: 'error',
    mime: {
      'text/x-typescript': ['ts', 'tsx']
    },
    karmaTypescriptConfig: {
      compilerOptions: {
          extendedDiagnostics: true,  
          allowJs: true, 
          outDir: "./dist",
          moduleResolution: "node",   
          strict: false, 
          sourceMap: true,
          module: "commonjs",
          "target": "ESNEXT",
          lib: ["DOM", "ESNext"],
          esModuleInterop: true,
          types: ["node"]      
      },
      include: ["tests/**/*.ts", "lib/**/*.ts"],
      reports:
      {
          "html": "coverage",
          "text-summary": ""
      },
      bundlerOptions: {
      entrypoints: /tests.*\.ts$/
      }    
    },
  });
};
