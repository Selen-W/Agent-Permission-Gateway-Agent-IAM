import { describe, expect, it } from 'vitest'
import { compileGlob, matchCommand, matchHost, tokenize } from '../src/glob.ts'

describe('compileGlob', () => {
  it('matches literal strings', () => {
    expect(compileGlob('git status')('git status')).toBe(true)
    expect(compileGlob('git status')('git push')).toBe(false)
  })

  it('matches * within a segment', () => {
    const matcher = compileGlob('github.*')
    expect(matcher('github.create-repo')).toBe(true)
    expect(matcher('github.com')).toBe(true)
    expect(matcher('github')).toBe(false)
    expect(matcher('githubx')).toBe(false)
  })

  it('does not let * cross / or :', () => {
    const matcher = compileGlob('fs.*')
    expect(matcher('fs.read')).toBe(true)
    expect(matcher('fs/read')).toBe(false)
  })

  it('matches ** across segments', () => {
    const matcher = compileGlob('./workspace/**')
    expect(matcher('./workspace/src/main.ts')).toBe(true)
    expect(matcher('./workspace/')).toBe(true)
    expect(matcher('./other/file.ts')).toBe(false)
  })

  it('matches ? as a single char', () => {
    const matcher = compileGlob('feature/?')
    expect(matcher('feature/a')).toBe(true)
    expect(matcher('feature/ab')).toBe(false)
  })

  it('matches {a,b} alternation', () => {
    const matcher = compileGlob('branch-{main,master}')
    expect(matcher('branch-main')).toBe(true)
    expect(matcher('branch-master')).toBe(true)
    expect(matcher('branch-dev')).toBe(false)
  })

  it('fails closed on malformed patterns', () => {
    const matcher = compileGlob('a{b')
    expect(matcher('a{b')).toBe(true)
    expect(matcher('ab')).toBe(false)
  })

  it('matches * for everything', () => {
    expect(compileGlob('*')('anything.at.all')).toBe(true)
  })
})

describe('matchCommand', () => {
  it('matches token prefixes', () => {
    expect(matchCommand('git push', 'git push origin main')).toBe(true)
    expect(matchCommand('git push', 'git push')).toBe(true)
    expect(matchCommand('git push', 'git pushy branch')).toBe(false)
  })

  it('requires the command to have at least the pattern tokens', () => {
    expect(matchCommand('git push origin', 'git push')).toBe(false)
  })

  it('honors globs per token', () => {
    expect(matchCommand('rm -rf *', 'rm -rf ./build')).toBe(true)
    expect(matchCommand('rm -rf *', 'rm -rf /')).toBe(true)
    expect(matchCommand('git checkout feature/*', 'git checkout feature/login')).toBe(true)
  })

  it('handles quoted tokens', () => {
    // A quoted pattern token is one token even when it contains a space.
    expect(matchCommand('echo "hello world"', 'echo "hello world"')).toBe(true)
    expect(matchCommand('echo "hello world"', 'echo hello')).toBe(false)
    expect(matchCommand('echo hello', 'echo hello world')).toBe(true)
  })
})

describe('matchHost', () => {
  it('matches exact hosts', () => {
    expect(matchHost('github.com', 'github.com')).toBe(true)
    expect(matchHost('github.com', 'gitlab.com')).toBe(false)
  })

  it('matches subdomains of bare domains', () => {
    expect(matchHost('github.com', 'api.github.com')).toBe(true)
    expect(matchHost('github.com', 'notgithub.com')).toBe(false)
  })

  it('matches wildcard patterns', () => {
    expect(matchHost('*.npmjs.org', 'registry.npmjs.org')).toBe(true)
    expect(matchHost('*.npmjs.org', 'npmjs.org')).toBe(false)
    expect(matchHost('*', 'anything.example')).toBe(true)
  })
})

describe('tokenize', () => {
  it('splits on whitespace and strips quotes', () => {
    expect(tokenize('git push origin "feature/x"')).toEqual(['git', 'push', 'origin', 'feature/x'])
    expect(tokenize("rm -rf './build dir'")).toEqual(['rm', '-rf', './build dir'])
  })
})
