'use strict';
// Facts about where the seven npm packages come from, shared by sync-version.js,
// verify-package-archives.js and verify-published-platform.js.
//
// npm publishes a provenance attestation (`npm publish --provenance`) only when each
// package.json's `repository.url` names the repository that ran the publish. A package
// without the field, or with a different one, makes the publish fail AFTER the build matrix
// has already succeeded, so every check below runs before anything is published.

const REPOSITORY_URL = 'git+https://github.com/FerroxLabs/fuigo.git';
const NPM_DIR = 'crates/codegen/fuigo-pager/npm';

/** The `repository` field for the package whose directory under npm/ is `dirName`. */
function repositoryFor(dirName) {
    return {type: 'git', url: REPOSITORY_URL, directory: `${NPM_DIR}/${dirName}`};
}

/** `git+https://github.com/<owner>/<repo>.git` for a GITHUB_REPOSITORY value. */
function repositoryUrlFor(githubRepository) {
    return `git+https://github.com/${githubRepository}.git`;
}

/**
 * Problems with a parsed package.json's `repository` field, as strings (empty when fine).
 * `githubRepository` (the Actions GITHUB_REPOSITORY, optional) is the repository that will
 * run the publish: npm refuses provenance when it differs from `repository.url`.
 */
function repositoryProblems(manifest, dirName, githubRepository) {
    const want = repositoryFor(dirName);
    const repo = manifest.repository;
    const problems = [];
    if (repo === undefined || repo === null) {
        return [`${manifest.name}: package.json has no "repository" field (npm provenance requires it)`];
    }
    if (typeof repo !== 'object' || repo.type !== want.type || repo.url !== want.url
        || repo.directory !== want.directory) {
        problems.push(`${manifest.name}: repository is ${JSON.stringify(repo)}, expected ${JSON.stringify(want)}`);
    }
    if (githubRepository && repo && repo.url !== repositoryUrlFor(githubRepository)) {
        problems.push(`${manifest.name}: repository.url ${repo.url} is not the publishing repository `
            + `${repositoryUrlFor(githubRepository)}; npm would refuse the provenance attestation`);
    }
    return problems;
}

module.exports = {REPOSITORY_URL, NPM_DIR, repositoryFor, repositoryUrlFor, repositoryProblems};
