
# PSUID
[![JavaScript Style Guide](https://cdn.rawgit.com/standard/standard/master/badge.svg)](https://github.com/standard/standard)

A sortable unique id containing a hash of a generated process fingerprint along with random bytes, a timestamp, and a counter.

<br />

## Table of Contents
- [ Installation ](#install)
- [ Components ](#components)
- [ Usage ](#usage)

<br />

<a name="install"></a>
## Install

```console
npm i psuid
```

<br />

<a name="components"></a>
## Components:

### 4 byte timestamp
### 2 byte counter
### 9 random bytes
### 5 byte process fingerprint hashed using SHA-3

<br />

<a name="usage"></a>
## Usage


```js
import PSUID from 'psuid'

const psuid = new PSUID()
const psuidString = psuid.toString() // EK2RJBUM-WUUXMV63-K8BDY49Z-1K3GS472
const psuidRevived = new PSUID('EK2RJBUM-WUUXMV63-K8BDY49Z-1K3GS472')
```
