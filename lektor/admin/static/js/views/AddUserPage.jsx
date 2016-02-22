'use strict';

var React = require('react');
var Router = require('react-router');

var Component = require('../components/Component');

var utils = require('../utils');

class AddUserPage extends Component {
  handleSubmit(e) {
    e.preventDefault();

    var username = e.target.elements['username'].value;
    if (!username) {
      return;
    }

    utils.request('/add-user', {
      json: {username: username},
      method: 'POST'
    }).then((resp) => {
      window.location = utils.getCanonicalUrl('/set_password_link/' + username + '/' + resp.tmp_token + '/True');
    });

  }

  render() {
    return (
      <div>
        <h1>Add a User</h1>
        <form onSubmit={this.handleSubmit}>
          <p>Username <input type="text" name="username"/></p>
          <input type="submit" value="Post" />
        </form>
      </div>
    );
  }
}

module.exports = AddUserPage;
