'use strict';

var React = require('react');
var Router = require('react-router');

var Component = require('../components/Component');
var utils = require('../utils');

class SetPasswordLinkPage extends Component {
  renderMessage() {
    var query = this.props.location.query,
        username = query.username,
        new_user = query.new_user;

    if (new_user) {
      return (
        <p>Welcome to the team! You can log in with username <strong>{username}</strong> at the following link:</p>
      );
    } else {
      return (
        <p>Hey {username}, you can reset your password at the following link:</p>
      );
    }
  }

  render() {
    var query = this.props.location.query,
        username = query.username,
        link = query.link;

    return (
      <div>
        <h1>Added user {username}</h1>
        <p>Send {username} a message like the following:</p>
        <blockquote>
          {this.renderMessage()}
          <a href={link}>{link}</a>
        </blockquote>
      </div>
    );
  }
}

module.exports = SetPasswordLinkPage;
