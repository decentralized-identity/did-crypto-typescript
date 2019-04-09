module.exports = function(config) { 
  config.set({

      frameworks: ["jasmine", "karma-typescript"],

      files: [
        //{ pattern: "tests/**/*.ts" },
        //{ pattern: "lib//index.ts", served: false, included:false },
        { pattern: "dist/lib/**/*.js", served: true },
        { pattern: "tests/DidKey.spec.browser.ts", served: true, watched: true }
      ],

      "exclude": [
        "lib/**/*.d.ts"
    ],

      preprocessors: {
        "tests/**/*spec.browser.ts": ["karma-typescript"]
    },

      karmaTypescriptConfig: {
          compilerOptions: {
              module: "umd",
              outDir: "./dist",
              moduleResolution: "node",   
              strict: true, 
              sourceMap: true,
              target: "es2018",
              lib: ["DOM", "es2018"],
              esModuleInterop: true      
          },
          include: ["tests/**/*.ts", "lib/**/*.ts"],
          reports:
          {
              "html": "coverage",
              "text-summary": ""
          }
      },
      
      mime: {
        'text/x-typescript': ['ts', 'tsx']
      },

      reporters: ["dots", "karma-typescript"],

      browsers: ["Chrome"],

      singleRun: true
  });
};
