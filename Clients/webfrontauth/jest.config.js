module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  setupFiles: [ 'jest-localstorage-mock' ],
  reporters: [
    [
      "jest-nyancat-reporter",
      {
        "suppressErrorReporter": false
      }
    ]
  ]
};
