import makeSession from "fetch-cookie";

export class HttpError extends Error {
  constructor(location, statusCode, details) {
	super(details);
  }
}

export default class Authenticator {
  #email;
  #password;
  #session;
  
  constructor(email, password, session = makeSession(fetch)) {
	this.#email = email;
	this.#password = password;
	this.#session = session;
  }

  async login(email = this.#email, password = this.#password) {
	return this.#zero()
	  .then(this.#one.bind(this))
	  .then(this.#two.bind(this))
	  .then(this.#three.bind(this))
	  .then((state) => this.#four(state, email))
	  .then((state) => this.#five(state, email, password))
	  .then(this.#six.bind(this))
	  .then(this.#seven.bind(this));
  }

  refresh() {
	return this.#seven();
  }

  async #zero() {
	return (
	  await (
		await this.#session(
		  "https://explorer.api.openai.com/api/auth/csrf"
		)
	  ).json()
	).csrfToken;
  }

  async #one(csrfToken) {
	return (
	  await (
		await this.#session(
		  "https://explorer.api.openai.com/api/auth/signin/auth0?prompt=login",
		  {
			method: "POST",
			body: new URLSearchParams({
			  callbackUrl: "/",
			  csrfToken,
			  json: true,
			}),
			headers: {
			  "Content-Type": "application/x-www-form-urlencoded",
			},
		  }
		)
	  ).json()
	).url;
  }

  async #two(url) {
	const response = await this.#session(url, {
	  redirect: "manual",
	});
	return (await response.text()).slice(48);
  }

  async #three(state) {
	const response = await this.#session(
	  `https://auth0.openai.com/u/login/identifier?state=${state}`
	);
	return state;
  }

  async #four(state, username) {
	const response = await this.#session(
	  `https://auth0.openai.com/u/login/identifier?state=${state}`,
	  {
		method: "POST",
		body: new URLSearchParams({
		  state,
		  username,
		  "js-available": false,
		  "webauthn-available": true,
		  "is-brave": false,
		  "webauthn-platform-available": true,
		  action: "default",
		}),
		headers: {
		  "content-type": "application/x-www-form-urlencoded",
		},
	  }
	);
	return state;
  }

  async #five(state, username, password) {
	const response = await this.#session(
	  `https://auth0.openai.com/u/login/password?state=${state}`,
	  {
		method: "POST",
		body: new URLSearchParams({
		  state,
		  username,
		  password,
		  action: "default",
		}),
		headers: {
		  "content-type": "application/x-www-form-urlencoded",
		},
		redirect: "manual",
	  }
	);
	return (await response.text()).slice(46);
  }

  async #six(state) {
	await this.#session(
	  `https://auth0.openai.com/authorize/resume?state=${state}`
	);
  }

  async #seven() {
	const response = await this.#session(
	  "https://explorer.api.openai.com/api/auth/session"
	);
	const { accessToken } = await response.json();
	return {
	  accessToken,
	  cookie: response.headers.get("set-cookie").split(";")[0],
	};
  }
}
