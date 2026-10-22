// Every push to main releases. Conventional Commits are welcome but not required:
// - a breaking change (`feat!:` or a `BREAKING CHANGE:` footer) is a major release,
// - `feat:` is a minor release,
// - anything else, including a plain message like "Fix the renewal date", is a patch release.

// Only these prefixes count as conventional, so a plain message that happens to contain a
// colon ("Note: ...") still lands in the release notes instead of being dropped.
const TYPES = 'feat|fix|perf|refactor|chore|docs|style|test|build|ci|revert';

const parserOpts = {
	headerPattern: new RegExp(`^(${TYPES})(?:\\((.*)\\))?!?: (.*)$`, 'i'),
	breakingHeaderPattern: new RegExp(`^(${TYPES})(?:\\((.*)\\))?!: (.*)$`, 'i'),
	noteKeywords: ['BREAKING CHANGE', 'BREAKING CHANGES', 'BREAKING-CHANGE'],
};

export default {
	branches: ['main'],
	plugins: [
		[
			'@semantic-release/commit-analyzer',
			{
				preset: 'conventionalcommits',
				parserOpts,
				releaseRules: [
					{ breaking: true, release: 'major' },
					{ type: '{feat,Feat,FEAT}', release: 'minor' },
					// Every commit has a hash, so everything else, conventional or not, is a patch.
					{ hash: '*', release: 'patch' },
				],
			},
		],
		[
			'@semantic-release/release-notes-generator',
			{
				preset: 'conventionalcommits',
				parserOpts,
				presetConfig: {
					types: [
						{ type: 'feat', section: 'Features' },
						{ type: 'fix', section: 'Bug Fixes' },
						{ type: 'perf', section: 'Performance Improvements' },
						{ type: '', section: 'Changes' },
						{ type: 'refactor', section: 'Refactoring' },
						{ type: 'chore', scope: 'deps', section: 'Dependency Updates' },
						{ type: 'chore', section: 'Chores' },
						{ type: 'docs', section: 'Documentation' },
						{ type: 'style', section: 'Styles' },
						{ type: 'test', section: 'Tests' },
						{ type: 'build', section: 'Build System' },
						{ type: 'ci', section: 'Continuous Integration' },
						{ type: 'revert', section: 'Reverts' },
					],
				},
			},
		],
		['@semantic-release/npm', { npmPublish: false }],
		['@semantic-release/git', { assets: ['package.json', 'package-lock.json'] }],
		'@semantic-release/github',
	],
};
