/*-
 * Copyright (c) 2013 Weongyo Jeong <weongyo@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

function __domainValid__(url, value) {
    var i,
        domainParts = url.hostname.split('.').reverse(),
        newDomainParts = value.split('.').reverse();
    if (newDomainParts.length > 1) {
        for (i = 0;i < newDomainParts.length; i++) {
            if (!(newDomainParts[i] == domainParts[i]))
                return false;
        }
        return (true);
    }
    return (false);
};

function __extend__(a, b) {
    for (var i in b) {
	var g = b.__lookupGetter__(i);
	var s = b.__lookupSetter__(i);
	if (g || s) {
	    if (g)
		a.__defineGetter__(i, g);
	    if (s)
		a.__defineSetter__(i, s);
	} else
	    a[i] = b[i];
    }
    return a;
}

function __cookieString__(cookies, url) {
    var cookieString = "",
        domain, 
        path,
        name,
        i=0;
    for (domain in cookies) {
        if (domain == "" || domain == url.hostname) {
            for (path in cookies[domain]) {
                if (path == "/" || url.path.indexOf(path) > -1) {
                    for (name in cookies[domain][path]) {
                        cookieString += 
                            ((i++ > 0)?'; ':'') +
                            name + "=" + 
                            cookies[domain][path][name].value;
                    }
                }
            }
        }
    }
    return cookieString;
};

function __mergeCookie__(target, cookie, properties) {
    var name, now;
    if (!target[cookie.domain]) {
        target[cookie.domain] = {};
    }
    if (!target[cookie.domain][cookie.path]) {
        target[cookie.domain][cookie.path] = {};
    }
    for (name in properties) {
        now = new Date().getTime();
        target[cookie.domain][cookie.path][name] = {
            "value": properties[name],
            "secure": cookie.secure,
            "max-age": cookie['max-age'],
            "date-created": now,
            "expiration": (cookie['max-age'] === 0) ? 0 :
		now + cookie['max-age']
        };
    }
};

function __trim__( str ) {
    return (str || "").replace(/^\s+|\s+$/g,"");
}

function __setArray__( target, array ) {
    target.length = 0;
    Array.prototype.push.apply(target, array);
}

/*----------------------------------------------------------------------*/

JSON = function() {
    function f(n) {
        return n < 10 ? '0' + n : n;
    }

    Date.prototype.toJSON = function (key) {
        return this.getUTCFullYear()   + '-' +
             f(this.getUTCMonth() + 1) + '-' +
             f(this.getUTCDate())      + 'T' +
             f(this.getUTCHours())     + ':' +
             f(this.getUTCMinutes())   + ':' +
             f(this.getUTCSeconds())   + 'Z';
    };
    String.prototype.toJSON = function (key) {
        return String(this);
    };
    Number.prototype.toJSON =
    Boolean.prototype.toJSON = function (key) {
        return this.valueOf();
    };

    var cx = /[\u0000\u00ad\u0600-\u0604\u070f\u17b4\u17b5\u200c-\u200f\u2028-\u202f\u2060-\u206f\ufeff\ufff0-\uffff]/g,
        escapeable = /[\\\"\x00-\x1f\x7f-\x9f\u00ad\u0600-\u0604\u070f\u17b4\u17b5\u200c-\u200f\u2028-\u202f\u2060-\u206f\ufeff\ufff0-\uffff]/g,
        gap,
        indent,
        meta = {    // table of character substitutions
            '\b': '\\b',
            '\t': '\\t',
            '\n': '\\n',
            '\f': '\\f',
            '\r': '\\r',
            '"' : '\\"',
            '\\': '\\\\'
        },
        rep;

    function quote(string) {
        escapeable.lastIndex = 0;
        return escapeable.test(string) ?
            '"' + string.replace(escapeable, function (a) {
                var c = meta[a];
                if (typeof c === 'string') {
                    return c;
                }
                return '\\u' + ('0000' +
                        (+(a.charCodeAt(0))).toString(16)).slice(-4);
            }) + '"' :
            '"' + string + '"';
    }

    function str(key, holder) {
        var i,          // The loop counter.
            k,          // The member key.
            v,          // The member value.
            length,
            mind = gap,
            partial,
            value = holder[key];

        if (value && typeof value === 'object' &&
                typeof value.toJSON === 'function') {
            value = value.toJSON(key);
        }
        if (typeof rep === 'function') {
            value = rep.call(holder, key, value);
        }

        switch (typeof value) {
        case 'string':
            return quote(value);

        case 'number':
            return isFinite(value) ? String(value) : 'null';

        case 'boolean':
        case 'null':

            return String(value);
            
        case 'object':
            if (!value)
                return 'null';
            gap += indent;
            partial = [];

            if (typeof value.length === 'number' &&
                    !(value.propertyIsEnumerable('length'))) {

                length = value.length;
                for (i = 0; i < length; i += 1) {
                    partial[i] = str(i, value) || 'null';
                }
                
                v = partial.length === 0 ? '[]' :
                    gap ? '[\n' + gap +
                            partial.join(',\n' + gap) + '\n' +
                                mind + ']' :
                          '[' + partial.join(',') + ']';
                gap = mind;
                return v;
            }

            if (rep && typeof rep === 'object') {
                length = rep.length;
                for (i = 0; i < length; i += 1) {
                    k = rep[i];
                    if (typeof k === 'string') {
                        v = str(k, value);
                        if (v) {
                            partial.push(quote(k) + (gap ? ': ' : ':') + v);
                        }
                    }
                }
            } else {
                for (k in value) {
                    if (Object.hasOwnProperty.call(value, k)) {
                        v = str(k, value);
                        if (v) {
                            partial.push(quote(k) + (gap ? ': ' : ':') + v);
                        }
                    }
                }
            }

            v = partial.length === 0 ? '{}' :
                gap ? '{\n' + gap + partial.join(',\n' + gap) + '\n' +
                        mind + '}' : '{' + partial.join(',') + '}';
            gap = mind;
            return v;
        }
    }

    return {
        stringify: function (value, replacer, space) {
            var i;

            gap = '';
            indent = '';

            if (typeof space === 'number') {
                for (i = 0; i < space; i += 1) {
                    indent += ' ';
                }

            } else if (typeof space === 'string') {
                indent = space;
            }

            rep = replacer;
            if (replacer && typeof replacer !== 'function' &&
                    (typeof replacer !== 'object' ||
                     typeof replacer.length !== 'number')) {
                throw new Error('JSON.stringify');
            }

            return str('', {'': value});
        },


        parse: function (text, reviver) {
            var j;

            function walk(holder, key) {
                var k, v, value = holder[key];
                if (value && typeof value === 'object') {
                    for (k in value) {
                        if (Object.hasOwnProperty.call(value, k)) {
                            v = walk(value, k);
                            if (v !== undefined) {
                                value[k] = v;
                            } else {
                                delete value[k];
                            }
                        }
                    }
                }
                return reviver.call(holder, key, value);
            }

            cx.lastIndex = 0;
            if (cx.test(text)) {
                text = text.replace(cx, function (a) {
                    return '\\u' + ('0000' +
                            (+(a.charCodeAt(0))).toString(16)).slice(-4);
                });
            }

            if (/^[\],:{}\s]*$/.
test(text.replace(/\\(?:["\\\/bfnrt]|u[0-9a-fA-F]{4})/g, '@').
replace(/"[^"\\\n\r]*"|true|false|null|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?/g, ']').
replace(/(?:^|:|,)(?:\s*\[)+/g, ''))) {
        
                j = eval('(' + text + ')');

                return typeof reviver === 'function' ?
                    walk({'': j}, '') : j;
            }

            throw new SyntaxError('JSON.parse');
        }
    };
};

/*----------------------------------------------------------------------*/

var __cookies__;

ENVJS.cookies = {
    persistent: {},
    temporary: {}
};

ENVJS.setCookie = function(url, cookie) {
    var i,
        index,
        name,
        value,
        properties = {},
        attr,
        attrs;
    url = ENVJS.urlsplit(url);
    if (cookie)
        attrs = cookie.split(";");
    else
        return;
    cookie = {};
    cookie['domain'] = url.hostname;
    cookie['path'] = url.path||'/';
    for (i = 0;i < attrs.length; i++) {
        index = attrs[i].indexOf("=");
        if (index > -1) {
            name = __trim__(attrs[i].slice(0,index));
            value = __trim__(attrs[i].slice(index + 1));
            if (name == 'max-age') {
                cookie[name] = parseInt(value, 10);
            } else if (name == 'domain') {
                if (__domainValid__(url, value))
                    cookie['domain'] = value;
            } else if (name == 'path')
                cookie['path'] = value;
            else
                properties[name] = value;
        } else {
            if (attrs[i] == 'secure')
                cookie[attrs[i]] = true;
        }
    }
    if (!('max-age' in cookie)) {
        __mergeCookie__(ENVJS.cookies.temporary, cookie, properties);
    } else {
        __mergeCookie__(ENVJS.cookies.persistent, cookie, properties);
        ENVJS.saveCookies();
    }
};

ENVJS.getCookies = function(url) {
    var persisted;
    url = ENVJS.urlsplit(url);
    if (!__cookies__) {
        try {
            __cookies__ = true;
            try {
                persisted = ENVJS.loadCookies();
            } catch (e) {
            }   
            if (persisted) {
                __extend__(ENVJS.cookies.persistent, persisted);
            }
        } catch(e) {
            console.log('cookies not loaded %s', e)
        };
    }
    var temporary = __cookieString__(ENVJS.cookies.temporary, url),
        persistent =  __cookieString__(ENVJS.cookies.persistent, url);
    return (temporary + persistent);
};

ENVJS.normalizepath = function(path)
{
    if (!path || path === '/')
        return '/';
    var parts = path.split('/');
    var newparts = [];
    if (parts[0])
        newparts.push('');
    for (var i = 0; i < parts.length; ++i) {
        if (parts[i] === '..') {
            if (newparts.length > 1)
                newparts.pop();
            else
                newparts.push(parts[i]);
        } else if (parts[i] != '.')
            newparts.push(parts[i]);
    }
    path = newparts.join('/');
    if (!path)
        path = '/';
    return (path);
};

ENVJS.uri = function(path, base) {
    if (path.indexOf('javascript') === 0)
        return '';
    if (path.match('^[a-zA-Z]+://'))
        return ENVJS.urlnormalize(path);
    if (path.match('^//'))
        path = 'http:' + path;
    if (!base && document)
        base = document.baseURI;
    if (base === 'about:blank')
        base = '';
    if (!base)
        base = 'file://' +  ENVJS.getcwd() + '/';
    var newurl = ENVJS.urlnormalize(ENVJS.urljoin(base, path, false));
    return (newurl);
};

ENVJS.urljoin = function(base, url, allow_fragments)
{
    if (typeof allow_fragments === 'undefined')
        allow_fragments = true;
    var url_parts = ENVJS.urlsplit(url);
    if (url_parts.scheme) {
        if (! allow_fragments)
            return url;
        else
            return ENVJS.urldefrag(url)[0];
    }
    var base_parts = ENVJS.urlsplit(base);
    if (!base_parts.scheme)
        base_parts.scheme = url_parts.scheme;
    if (!base_parts.netloc || !base_parts.hostname) {
        base_parts.netloc = url_parts.netloc;
        base_parts.hostname = url_parts.hostname;
        base_parts.port = url_parts.port;
    }
    if (url_parts.path.length > 0) {
        if (url_parts.path.charAt(0) == '/')
            base_parts.path = url_parts.path;
        else {
            var idx = base_parts.path.lastIndexOf('/');
            if (idx == -1)
                base_parts.path = url_parts.path;
            else
                base_parts.path = base_parts.path.substr(0,idx) + '/' +
                    url_parts.path;
        }
    }
    base_parts.path = ENVJS.normalizepath(base_parts.path);
    base_parts.query = url_parts.query;
    if (allow_fragments)
        base_parts.fragment = url_parts.fragment;
    else
        base_parts.fragment = '';
    return ENVJS.urlunsplit(base_parts);
};

ENVJS.urlnormalize = function(url) {
    var parts = ENVJS.urlsplit(url);
    switch (parts.scheme) {
    case 'file':
        parts.query = '';
        parts.fragment = '';
        break;
    case 'http':
    case 'https':
        if ((parts.scheme === 'http' && parts.port == 80) ||
            (parts.scheme === 'https' && parts.port == 443)) {
            parts.port = null;
            parts.netloc = parts.hostname;
        }
        break;
    default:
        return url;
    }
    parts.path = ENVJS.normalizepath(parts.path);
    return ENVJS.urlunsplit(parts);
};

ENVJS.urlsplit = function(url, default_scheme, allow_fragments) {
    var leftover;

    if (typeof allow_fragments === 'undefined')
	allow_fragments = true;
    var fullurl = /^([A-Za-z]+)?(:?\/\/)([0-9.\-A-Za-z]*)(?::(\d+))?(.*)$/;
    var parse_leftovers = /([^?#]*)?(?:\?([^#]*))?(?:#(.*))?$/;
    var o = {};
    var parts = url.match(fullurl);
    if (parts) {
	o.scheme = parts[1] || default_scheme || '';
	o.hostname = parts[3].toLowerCase() || '';
	o.port = parseInt(parts[4],10) || '';
	o.netloc = parts[3];
	if (parts[4])
	    o.netloc += ':' + parts[4];
	leftover = parts[5];
    } else {
	o.scheme = default_scheme || '';
	o.netloc = '';
	o.hostname = '';
	leftover = url;
    }
    o.scheme = o.scheme.toLowerCase();
    parts = leftover.match(parse_leftovers);
    o.path =  parts[1] || '';
    o.query = parts[2] || '';
    if (allow_fragments) {
	o.fragment = parts[3] || '';
    } else {
	o.fragment = '';
    }
    return (o);
};

ENVJS.urlunsplit = function(o) {
    var s = '';
    if (o.scheme)
        s += o.scheme + '://';
    if (o.netloc) {
        if (s == '')
            s += '//';
        s +=  o.netloc;
    } else if (o.hostname) {
        if (s == '')
            s += '//';
        s += o.hostname;
        if (o.port)
            s += ':' + o.port;
    }
    if (o.path)
        s += o.path;
    if (o.query)
        s += '?' + o.query;
    if (o.fragment)
        s += '#' + o.fragment;
    return (s);
};

/*----------------------------------------------------------------------*/

DOMImplementation = function() {
    this.preserveWhiteSpace = false;
    this.namespaceAware = true;
    this.errorChecking  = true;
};

/*----------------------------------------------------------------------*/

var __appendChild__ = function(nodelist, newChild) {
    if (newChild.nodeType == Node.DOCUMENT_FRAGMENT_NODE)
	Array.prototype.push.apply(nodelist, newChild.childNodes.toArray());
    else
	Array.prototype.push.apply(nodelist, [newChild]);
};

var __isAncestor__ = function(target, node) {
    return ((target == node) ||
	    ((target.parentNode) && (__isAncestor__(target.parentNode, node))));
};

var __ownerDocument__ = function(node) {
    return (node.nodeType == Node.DOCUMENT_NODE) ? node : node.ownerDocument;
};

var __findItemIndex__ = function(nodelist, node) {
    var ret = -1, i;

    for (i = 0; i < nodelist.length; i++) {
        if (nodelist[i] === node) {
            ret = i;
            break;
        }
    }
    return (ret);
};

var __getElementsByTagNameRecursive__ = function (elem, tagname, nodeList) {
    if (elem.nodeType == Node.ELEMENT_NODE ||
	elem.nodeType == Node.DOCUMENT_NODE) {
        if (elem.nodeType !== Node.DOCUMENT_NODE &&
            ((elem.nodeName.toUpperCase() == tagname.toUpperCase()) ||
             (tagname == "*")) ) {
            __appendChild__(nodeList, elem);
        }
        for (var i = 0; i < elem.childNodes.length; i++) {
            nodeList =
		__getElementsByTagNameRecursive__(elem.childNodes.item(i),
						  tagname, nodeList);
        }
    }

    return (nodeList);
};

var __insertBefore__ = function(nodelist, newChild, refChildIndex) {
    if ((refChildIndex >= 0) && (refChildIndex <= nodelist.length)) {
        if (newChild.nodeType == Node.DOCUMENT_FRAGMENT_NODE) {
            Array.prototype.splice.apply(nodelist,
                [refChildIndex, 0].concat(newChild.childNodes.toArray()));
        } else {
            Array.prototype.splice.apply(nodelist,[refChildIndex, 0, newChild]);
        }
    }
};

var __removeChild__ = function(nodelist, refChildIndex) {
    var ret = null;

    if (refChildIndex > -1) {
        ret = nodelist[refChildIndex];
        Array.prototype.splice.apply(nodelist,[refChildIndex, 1]);
    }
    return (ret);
};

Node = function(ownerDocument) {
    this.ownerDocument = ownerDocument;
    this.childNodes = new NodeList(ownerDocument, this);
};
Node.ELEMENT_NODE			= 1;
Node.ATTRIBUTE_NODE			= 2;
Node.TEXT_NODE				= 3;
Node.CDATA_SECTION_NODE			= 4;
Node.ENTITY_REFERENCE_NODE		= 5;
Node.ENTITY_NODE			= 6;
Node.PROCESSING_INSTRUCTION_NODE	= 7;
Node.COMMENT_NODE			= 8;
Node.DOCUMENT_NODE			= 9;
Node.DOCUMENT_TYPE_NODE			= 10;
Node.DOCUMENT_FRAGMENT_NODE		= 11;
Node.NOTATION_NODE			= 12;
Node.NAMESPACE_NODE			= 13;

Node.DOCUMENT_POSITION_EQUAL		= 0x00;
Node.DOCUMENT_POSITION_DISCONNECTED	= 0x01;
Node.DOCUMENT_POSITION_PRECEDING	= 0x02;
Node.DOCUMENT_POSITION_FOLLOWING	= 0x04;
Node.DOCUMENT_POSITION_CONTAINS		= 0x08;
Node.DOCUMENT_POSITION_CONTAINED_BY	= 0x10;
Node.DOCUMENT_POSITION_IMPLEMENTATION_SPECIFIC = 0x20;
__extend__(Node.prototype, {
    appendChild: function(newChild) {
	if (!newChild)
	    return null;
	if (__ownerDocument__(this).implementation.errorChecking) {
	    if (this._readonly)
		throw(new DOMException(DOMException.NO_MODIFICATION_ALLOWED_ERR));
	    if (__ownerDocument__(this) != __ownerDocument__(this))
		throw(new DOMException(DOMException.WRONG_DOCUMENT_ERR));
	    if (__isAncestor__(this, newChild))
	      throw(new DOMException(DOMException.HIERARCHY_REQUEST_ERR));
	}
	var newChildParent = newChild.parentNode;
	if (newChildParent)
	    newChildParent.removeChild(newChild);
	__appendChild__(this.childNodes, newChild);

	if (newChild.nodeType == Node.DOCUMENT_FRAGMENT_NODE) {
	    if (newChild.childNodes.length > 0) {
		for (var ind = 0; ind < newChild.childNodes.length; ind++)
		    newChild.childNodes[ind].parentNode = this;
		if (this.lastChild) {
		    this.lastChild.nextSibling = newChild.childNodes[0];
		    newChild.childNodes[0].previousSibling = this.lastChild;
		    this.lastChild = newChild.childNodes[newChild.childNodes.length-1];
		} else {
		    this.lastChild = newChild.childNodes[newChild.childNodes.length-1];
		    this.firstChild = newChild.childNodes[0];
		}
	    }
	} else {
	    newChild.parentNode = this;
	    if (this.lastChild) {
		this.lastChild.nextSibling = newChild;
		newChild.previousSibling = this.lastChild;
		this.lastChild = newChild;
	    } else {
		this.lastChild = newChild;
		this.firstChild = newChild;
	    }
       }
       return newChild;
    },
    getElementsByTagName : function(tagname) {
        var nodelist = new NodeList(__ownerDocument__(this));
        for (var i = 0; i < this.childNodes.length; i++) {
            __getElementsByTagNameRecursive__(this.childNodes.item(i),
                                              tagname, nodelist);
        }
        return (nodelist);
    },
    insertBefore : function(newChild, refChild) {
        var prevNode;

        if (newChild == null)
            return (newChild);
        if (refChild == null) {
            this.appendChild(newChild);
            return (this.newChild);
        }
        if (__ownerDocument__(this).implementation.errorChecking) {
            if (this._readonly) {
                throw(new DOMException(DOMException.NO_MODIFICATION_ALLOWED_ERR));
            }
            if (__ownerDocument__(this) != __ownerDocument__(newChild)) {
                throw(new DOMException(DOMException.WRONG_DOCUMENT_ERR));
            }
            if (__isAncestor__(this, newChild)) {
                throw(new DOMException(DOMException.HIERARCHY_REQUEST_ERR));
            }
        }
        if (refChild) {
            var itemIndex = __findItemIndex__(this.childNodes, refChild);
            if (__ownerDocument__(this).implementation.errorChecking &&
		(itemIndex < 0)) {
                throw(new DOMException(DOMException.NOT_FOUND_ERR));
            }
            var newChildParent = newChild.parentNode;
            if (newChildParent)
                newChildParent.removeChild(newChild);
            __insertBefore__(this.childNodes, newChild, itemIndex);
            prevNode = refChild.previousSibling;
            if (newChild.nodeType == Node.DOCUMENT_FRAGMENT_NODE) {
                if (newChild.childNodes.length > 0) {
                    for (var ind = 0; ind < newChild.childNodes.length; ind++)
                        newChild.childNodes[ind].parentNode = this;
                    refChild.previousSibling =
			newChild.childNodes[newChild.childNodes.length-1];
                }
            } else {
                newChild.parentNode = this;
                refChild.previousSibling = newChild;
            }
        } else {
            prevNode = this.lastChild;
            this.appendChild(newChild);
        }
        if (newChild.nodeType == Node.DOCUMENT_FRAGMENT_NODE) {
            if (newChild.childNodes.length > 0) {
                if (prevNode)
                    prevNode.nextSibling = newChild.childNodes[0];
                else
                    this.firstChild = newChild.childNodes[0];
                newChild.childNodes[0].previousSibling = prevNode;
                newChild.childNodes[newChild.childNodes.length-1].nextSibling =
		    refChild;
            }
        } else {
            if (prevNode)
                prevNode.nextSibling = newChild;
            else
                this.firstChild = newChild;
            newChild.previousSibling = prevNode;
            newChild.nextSibling     = refChild;
        }
        return (newChild);
    },
    removeChild: function(oldChild) {
	if (!oldChild)
            return (null);
        if (__ownerDocument__(this).implementation.errorChecking &&
            (this._readonly || oldChild._readonly)) {
            throw(new DOMException(DOMException.NO_MODIFICATION_ALLOWED_ERR));
        }
        var itemIndex = __findItemIndex__(this.childNodes, oldChild);
        if (__ownerDocument__(this).implementation.errorChecking &&
	    itemIndex < 0) {
            throw(new DOMException(DOMException.NOT_FOUND_ERR));
        }
        __removeChild__(this.childNodes, itemIndex);
        oldChild.parentNode = null;
        if (oldChild.previousSibling)
            oldChild.previousSibling.nextSibling = oldChild.nextSibling;
        else
            this.firstChild = oldChild.nextSibling;
        if (oldChild.nextSibling)
            oldChild.nextSibling.previousSibling = oldChild.previousSibling;
        else
            this.lastChild = oldChild.previousSibling;
        oldChild.previousSibling = null;
        oldChild.nextSibling = null;
        return oldChild;
    },
});

/*----------------------------------------------------------------------*/

var $events = [{}];

function __addEventListener__(target, type, fn, phase) {
    phase = !!phase?"CAPTURING":"BUBBLING";
    if (!target.uuid)
        target.uuid = $events.length+'';
    if (!$events[target.uuid])
        $events[target.uuid] = {};
    if (!$events[target.uuid][type]) {
        $events[target.uuid][type] = {
            CAPTURING : [],
            BUBBLING : []
        };
    }
    if ($events[target.uuid][type][phase].indexOf(fn) < 0 )
        $events[target.uuid][type][phase].push(fn);
}

EventTarget = function() {};
EventTarget.prototype.addEventListener = function(type, fn, phase) {
    __addEventListener__(this, type, fn, phase);
};
EventTarget.prototype.removeEventListener = function(type, fn) {
    DUMP(this);
};
EventTarget.prototype.dispatchEvent = function(event, bubbles) {
    DUMP(this);
};
__extend__(Node.prototype, EventTarget.prototype);

/*----------------------------------------------------------------------*/

NodeList = function(ownerDocument, parentNode) {
    this.length = 0;
    this.parentNode = parentNode;
    this.ownerDocument = ownerDocument;
    this._readonly = false;
    __setArray__(this, []);
};
__extend__(NodeList.prototype, {
    item : function(index) {
        var ret = null;
        if ((index >= 0) && (index < this.length)) {
            ret = this[index];
        }
        return (ret);
    },
});

/*----------------------------------------------------------------------*/

Attr = function(ownerDocument) {
    Node.apply(this, arguments);
    this.ownerElement = null;
};
Attr.prototype = new Node();
__extend__(Attr.prototype, {
});

/*----------------------------------------------------------------------*/

CharacterData = function(ownerDocument) {
    Node.apply(this, arguments);
};
CharacterData.prototype = new Node();
__extend__(CharacterData.prototype,{
});

/*----------------------------------------------------------------------*/

Comment = function(ownerDocument) {
    CharacterData.apply(this, arguments);
    this.nodeName  = "#comment";
};
Comment.prototype = new CharacterData();
__extend__(Comment.prototype, {
    get nodeType() {
        return Node.COMMENT_NODE;
    },
});

/*----------------------------------------------------------------------*/

DocumentFragment = function(ownerDocument) {
    Node.apply(this, arguments);
    this.nodeName  = "#document-fragment";
};
DocumentFragment.prototype = new Node();
__extend__(DocumentFragment.prototype,{
});

/*----------------------------------------------------------------------*/

Text = function(ownerDocument) {
    CharacterData.apply(this, arguments);
    this.nodeName  = "#text";
};
Text.prototype = new CharacterData();
__extend__(Text.prototype, {
    get nodeType(){
        return Node.TEXT_NODE;
    },
});

/*----------------------------------------------------------------------*/

var re_validName = /^[a-zA-Z_:][a-zA-Z0-9\.\-_:]*$/;
function __isValidName__(name) {
    return name.match(re_validName);
}

var re_invalidStringChars = /\x01|\x02|\x03|\x04|\x05|\x06|\x07|\x08|\x0B|\x0C|\x0E|\x0F|\x10|\x11|\x12|\x13|\x14|\x15|\x16|\x17|\x18|\x19|\x1A|\x1B|\x1C|\x1D|\x1E|\x1F|\x7F/;
function __isValidString__(name) {
    return (name.search(re_invalidStringChars) < 0);
}

Document = function(implementation, docParentWindow) {
    Node.apply(this, arguments);
    this.implementation = implementation;
    this.ownerDocument = null;
};
Document.prototype = new Node();
__extend__(Document.prototype, {
    createAttribute: function(name) {
        if (__ownerDocument__(this).implementation.errorChecking &&
            (!__isValidName__(name))) {
            throw(new DOMException(DOMException.INVALID_CHARACTER_ERR));
        }
        var node = new Attr(this);
        node.nodeName = name;
        return (node);
    },
    createComment: function(data) {
        var node = new Comment(this);
        node.data = data;
        return (node);
    },
    createDocumentFragment: function() {
        var node = new DocumentFragment(this);
        return (node);
    },
    createTextNode: function(data) {
        var node = new Text(this);
        node.data = data;
        return node;
    },
    get documentElement() {
	var i, length = this.childNodes ? this.childNodes.length : 0;

	for (i = 0; i < length; i++) {
	    if (this.childNodes[i].nodeType === Node.ELEMENT_NODE)
		return this.childNodes[i];
	}
	return null;
    },
    getElementById : function(elementId) {
        var retNode = null,
            node;
        var all = this.getElementsByTagName('*');
        for (var i=0; i < all.length; i++) {
            node = all[i];
            if (node.id == elementId) {
                retNode = node;
                break;
            }
        }
        return (retNode);
    },
    get nodeType() {
	return Node.DOCUMENT_NODE;
    },
});

/*----------------------------------------------------------------------*/

var __findNamedItemIndex__ = function(namednodemap, name, isnsmap) {
    var ret = -1;

    for (var i = 0; i < namednodemap.length; i++) {
        if (namednodemap[i].localName && name && isnsmap) {
            if (namednodemap[i].localName.toLowerCase() == name.toLowerCase()) {
                ret = i;
                break;
            }
        } else {
            if (namednodemap[i].name && name) {
                if (namednodemap[i].name.toLowerCase() == name.toLowerCase()) {
                    ret = i;
                    break;
                }
            }
        }
    }
    return (ret);
};

NamedNodeMap = function(ownerDocument, parentNode) {
    NodeList.apply(this, arguments);
    __setArray__(this, []);
};
NamedNodeMap.prototype = new NodeList();
__extend__(NamedNodeMap.prototype, {
    getNamedItem : function(name) {
        var ret = null;
        var itemIndex = __findNamedItemIndex__(this, name);

        if (itemIndex > -1)
            ret = this[itemIndex];
        return (ret);
    },
    setNamedItem : function(arg) {
	if (__ownerDocument__(this).implementation.errorChecking) {
            if (this.ownerDocument != arg.ownerDocument) {
		throw(new DOMException(DOMException.WRONG_DOCUMENT_ERR));
            }
            if (this._readonly ||
		(this.parentNode && this.parentNode._readonly)) {
		throw(new DOMException(DOMException.NO_MODIFICATION_ALLOWED_ERR));
            }
            if (arg.ownerElement && (arg.ownerElement != this.parentNode)) {
		throw(new DOMException(DOMException.INUSE_ATTRIBUTE_ERR));
            }
	}
	var itemIndex = __findNamedItemIndex__(this, arg.name);
	var ret = null;

	if (itemIndex > -1) {
            ret = this[itemIndex];
            if (__ownerDocument__(this).implementation.errorChecking &&
		ret._readonly) {
		throw(new DOMException(DOMException.NO_MODIFICATION_ALLOWED_ERR));
            } else {
		this[itemIndex] = arg;
		this[arg.name.toLowerCase()] = arg;
            }
	} else {
            Array.prototype.push.apply(this, [arg]);
            this[arg.name] = arg;
	}
	arg.ownerElement = this.parentNode;
	return (ret);
    },
 });

/*----------------------------------------------------------------------*/

Element = function(ownerDocument) {
    Node.apply(this, arguments);
    this.attributes = new NamedNodeMap(this.ownerDocument, this);
};
Element.prototype = new Node();
__extend__(Element.prototype, {
    getAttribute: function(name) {
        var ret = null;
        var attr = this.attributes.getNamedItem(name);

        if (attr)
            ret = attr.value;
        return (ret);
    },
    setAttribute: function (name, value) {
        var attr = this.attributes.getNamedItem(name);

        if (__ownerDocument__(this)) {
            if (attr === null || attr === undefined)
                attr = __ownerDocument__(this).createAttribute(name);
            if (__ownerDocument__(this).implementation.errorChecking) {
                if (attr._readonly) {
                    throw(new DOMException(DOMException.NO_MODIFICATION_ALLOWED_ERR));
                }
                if (!__isValidString__(value + '')) {
                    throw(new DOMException(DOMException.INVALID_CHARACTER_ERR));
                }
            }
            attr.value = value + '';
            this.attributes.setNamedItem(attr);
        } else {
           console.warn('Element has no owner document ' + this.tagName +
                '\n\t cant set attribute ' + name + ' = ' + value );
        }
    },
});

/*----------------------------------------------------------------------*/

History = function(owner) {
    var $current = 0,
        $history = [null],
        $owner = owner;

    return {
        go : function(target) {
            if (typeof target === "number") {
                target = $current + target;
                if (target > -1 && target < $history.length) {
                    if ($history[target].type === "hash") {
                        if ($owner.location) {
                            $owner.location.hash = $history[target].value;
                        }
                    } else {
                        if ($owner.location) {
                            $owner.location = $history[target].value;
                        }
                    }
                    $current = target;
                }
            } else {
                //TODO: walk through the history and find the 'best match'?
            }
        },
        get length() {
            return $history.length;
        },
        back : function(count) {
            if (count) {
                this.go(-count);
            } else {
                this.go(-1);
            }
        },
        get current() {
            return this.item($current);
        },
        get previous() {
            return this.item($current-1);
        },
        forward : function(count) {
            if (count) {
                this.go(count);
            } else {
                this.go(1);
            }
        },
        item: function(idx) {
            if (idx >= 0 && idx < $history.length) {
                return $history[idx];
            } else {
                return null;
            }
        },
        add: function(newLocation, type) {
            if (newLocation !== $history[$current]) {
                $history.slice(0, $current);
                $history.push({
                    type: type || 'href',
                    value: newLocation
                });
            }
        }
    };
};

/*----------------------------------------------------------------------*/

CSS2Properties = function(element) {
    return {
	get backgroundColor() {
	    return ('rgb(0,0,0)');
	},
    };
};

/*----------------------------------------------------------------------*/

var  __DOMElement__ = Element;

HTMLElement = function(ownerDocument) {
    __DOMElement__.apply(this, arguments);
};
HTMLElement.prototype = new Element();
__extend__(HTMLElement.prototype, {
    get style() {
        return this.getAttribute('style') || new CSS2Properties(this);
    },
});

/*----------------------------------------------------------------------*/

HTMLAnchorElement = function(ownerDocument) {
    HTMLElement.apply(this, arguments);
};
HTMLAnchorElement.prototype = new HTMLElement();

/*----------------------------------------------------------------------*/

HTMLBodyElement = function(ownerDocument) {
    HTMLElement.apply(this, arguments);
};
HTMLBodyElement.prototype = new HTMLElement();

/*----------------------------------------------------------------------*/

HTMLDivElement = function(ownerDocument) {
    HTMLElement.apply(this, arguments);
};
HTMLDivElement.prototype = new HTMLElement();

/*----------------------------------------------------------------------*/

HTMLHeadElement = function(ownerDocument) {
    HTMLElement.apply(this, arguments);
};
HTMLHeadElement.prototype = new HTMLElement();

/*----------------------------------------------------------------------*/

HTMLHtmlElement = function(ownerDocument) {
    HTMLElement.apply(this, arguments);
};
HTMLHtmlElement.prototype = new HTMLElement();
__extend__(HTMLHtmlElement.prototype, {
    toString: function() {
	return '[object HTMLHtmlElement]';
    }
});

/*----------------------------------------------------------------------*/

HTMLImageElement = function(ownerDocument) {
    HTMLElement.apply(this, arguments);
};
HTMLImageElement.prototype = new HTMLElement();

/*----------------------------------------------------------------------*/

var HTMLInputCommon = function(ownerDocument) {
    HTMLElement.apply(this, arguments);
};
HTMLInputCommon.prototype = new HTMLElement();

var HTMLTypeValueInputs = function(ownerDocument) {
    HTMLInputCommon.apply(this, arguments);
};
HTMLTypeValueInputs.prototype = new HTMLInputCommon();

var HTMLInputAreaCommon = function(ownerDocument) {
    HTMLTypeValueInputs.apply(this, arguments);
};
HTMLInputAreaCommon.prototype = new HTMLTypeValueInputs();

HTMLInputElement = function(ownerDocument) {
    HTMLInputAreaCommon.apply(this, arguments);
};
HTMLInputElement.prototype = new HTMLInputAreaCommon();

/*----------------------------------------------------------------------*/

HTMLOptionElement = function(ownerDocument) {
    HTMLInputCommon.apply(this, arguments);
    this._selected = null;
};
HTMLOptionElement.prototype = new HTMLInputCommon();

/*----------------------------------------------------------------------*/

HTMLParagraphElement = function(ownerDocument) {
    HTMLElement.apply(this, arguments);
};
HTMLParagraphElement.prototype = new HTMLElement();

/*----------------------------------------------------------------------*/

HTMLScriptElement = function(ownerDocument) {
    HTMLElement.apply(this, arguments);
};
HTMLScriptElement.prototype = new HTMLElement();

/*----------------------------------------------------------------------*/

HTMLSelectElement = function(ownerDocument) {
    HTMLTypeValueInputs.apply(this, arguments);
    this._oldIndex = -1;
};
HTMLSelectElement.prototype = new HTMLTypeValueInputs();

/*----------------------------------------------------------------------*/

HTMLTextAreaElement = function(ownerDocument) {
    HTMLInputAreaCommon.apply(this, arguments);
    this._rawvalue = null;
};
HTMLTextAreaElement.prototype = new HTMLInputAreaCommon();

/*----------------------------------------------------------------------*/

HTMLTitleElement = function(ownerDocument) {
    HTMLElement.apply(this, arguments);
};
HTMLTitleElement.prototype = new HTMLElement();

/*----------------------------------------------------------------------*/

HTMLDocument = function(implementation, ownerWindow, referrer) {
    Document.apply(this, arguments);
    this.referrer = referrer || '';
    this.baseURI = "about:blank";
    this.ownerWindow = ownerWindow;
};
HTMLDocument.prototype = new Document();
__extend__(HTMLDocument.prototype, {
    get cookie() {
        return ENVJS.getCookies(this.location + '');
    },
    set cookie(cookie) {
        return ENVJS.setCookie(this.location + '', cookie);
    },
    createElement: function(tagName) {
	var node;

	tagName = tagName.toUpperCase();
	switch (tagName) {
        case "A":
            node = new HTMLAnchorElement(this);
	    break;
        case "DIV":
            node = new HTMLDivElement(this);
	    break;
        case "BODY":
            node = new HTMLBodyElement(this);
	    break;
	case "HEAD":
	    node = new HTMLHeadElement(this);
	    break;
	case "HTML":
	    node = new HTMLHtmlElement(this);
	    break;
        case "INPUT":
            node = new HTMLInputElement(this);
	    break;
        case "OPTION":
            node = new HTMLOptionElement(this);
	    break;
        case "P":
            node = new HTMLParagraphElement(this);
	    break;
        case "SCRIPT":
            node = new HTMLScriptElement(this);
	    break;
        case "SELECT":
            node = new HTMLSelectElement(this);
	    break;
        case "TEXTAREA":
            node = new HTMLTextAreaElement(this);
	    break;
        case "TITLE":
            node = new HTMLTitleElement(this);
	    break;
	default:
	    DUMP(tagName);
	}
	node.nodeName  = tagName;
	return (node);
    },
    get documentElement() {
	var html = Document.prototype.__lookupGetter__('documentElement').apply(this,[]);
	if ( html === null) {
	    html = this.createElement('html');
	    this.appendChild(html);
	    html.appendChild(this.createElement('head'));
	    html.appendChild(this.createElement('body'));
	}
	return (html);
    },
    get domain() {
        var HOSTNAME = new RegExp('\/\/([^\:\/]+)'),
        matches = HOSTNAME.exec(this.baseURI);
        return matches && matches.length > 1 ? matches[1] : "";
    },
    set domain(value) {
        var i,
        domainParts = this.domain.split('.').reverse(),
        newDomainParts = value.split('.').reverse();
        if (newDomainParts.length > 1) {
            for (i = 0;i < newDomainParts.length; i++) {
                if (!(newDomainParts[i] === domainParts[i]))
                    return;
            }
            this.baseURI = this.baseURI.replace(domainParts.join('.'), value);
        }
    },
    get head(){
        if (!this.documentElement)
            this.appendChild(this.createElement('html'));
        var element = this.documentElement,
            length = element.childNodes.length,
            i;
        for (i = 0; i < length; i++) {
            if (element.childNodes[i].nodeType === Node.ELEMENT_NODE) {
                if (element.childNodes[i].tagName.toLowerCase() === 'head')
                    return element.childNodes[i];
            }
        }
        var head = element.appendChild(this.createElement('head'));
        return (head);
    },
    get location() {
        if (this.ownerWindow)
            return this.ownerWindow.location;
        else
            return this.baseURI;
    },
    set location(url) {
        this.baseURI = url;
        if (this.ownerWindow)
            this.ownerWindow.location = url;
    },
    open : function() {
        if (!this._writebuffer)
            this._writebuffer = [];
    },
    get title(){
        if (!this.documentElement)
            this.appendChild(this.createElement('html'));
        var title,
            head = this.head,
            length = head.childNodes.length,
            i;
        for (i = 0; i < length; i++) {
            if (head.childNodes[i].nodeType === Node.ELEMENT_NODE) {
                if (head.childNodes[i].tagName.toLowerCase() === 'title')
                    return head.childNodes[i].textContent;
            }
        }
        title = head.appendChild(this.createElement('title'));
        return title.appendChild(this.createTextNode('Untitled Document')).nodeValue;
    },
    set title(titleStr) {
        if (!this.documentElement)
            this.appendChild(this.createElement('html'));
        var title = this.title;
        title.textContent = titleStr;
    },
    write: function(htmlstring) {
        this.open();
        this._writebuffer.push(htmlstring);
    },
    writeln: function(htmlstring) {
        this.open();
        this._writebuffer.push(htmlstring + '\n');
    }
});

/*----------------------------------------------------------------------*/

Image = function(width, height) {
    HTMLElement.apply(this, [document]);
    this.width = parseInt(width, 10) || 0;
    this.height = parseInt(height, 10) || 0;
    this.nodeName = 'IMG';
};
Image.prototype = new HTMLImageElement();

/*----------------------------------------------------------------------*/

Location = function(url, doc, history) {
    var $url = url;
    var $document = doc ? doc : null;
    var $history = history ? history : null;
    var parts = ENVJS.urlsplit($url);

    return {
        get href() {
            return $url;
        },
        set href(url) {
	    ENVJS.collectURL(url);
            $url = url;
            if ($history)
                $history.add($url, 'href');
        },
        get search() {
            return (parts.query) ? '?' + parts.query : parts.query;
        },
        set search(s) {
            if (s[0] == '?') {
                s = s.substr(1);
            }
            parts.query = s;
            $url = Envjs.urlunsplit(parts);
            if ($history) {
                $history.add($url, 'search');
            }
            this.assign($url);
        },
    }
};

/*----------------------------------------------------------------------*/

Navigator = function() {
    return {
        get appCodeName() {
	    return ("Mozilla");
        },
        get appName() {
	    return ("Netscape");
        },
        get appVersion() {
	    return ("5.0 (X11; Linux x86_64) AppleWebKit/537.36" +
		    " (KHTML, like Gecko) Ubuntu Chromium/28.0.1500.71" +
		    " Chrome/28.0.1500.71 Safari/537.36");
        },
        get cookieEnabled() {
	    return (true);
        },
        javaEnabled: function() {
            return (true);
        },
        get mimeTypes() {
	    DUMP(this);
        },
        get platform() {
	    DUMP(this);
        },
        get plugins() {
	    return [];
        },
        get userAgent() {
	    return ("Mozilla/5.0 (X11; Linux x86_64)" +
		    " AppleWebKit/537.36 (KHTML, like Gecko)" +
		    " Ubuntu Chromium/28.0.1500.71 Chrome/28.0.1500.71" +
		    " Safari/537.36");
        }
    };
};

/*----------------------------------------------------------------------*/

var __top__ = function(_scope) {
    var _parent = _scope.parent;
    while (_scope && _parent && _scope !== _parent) {
        if (_parent === _parent.parent) {
            break;
        }
        _parent = _parent.parent;
    }
    return _parent || null;
};

Window = function(scope, parent, opener) {
    scope.__defineGetter__('window', function() {
	return scope;
    });
    var $htmlImplementation = new DOMImplementation();
    var $document = new HTMLDocument($htmlImplementation, scope);
    var $history = new History();
    var $location = new Location(ENVJS.getURL(), $document, $history);
    var $navigator = new Navigator();
    var $parent = parent;
    __extend__(scope, EventTarget.prototype);
    return __extend__(scope, {
        alert : function(message) {
            DUMP(message);
        },
	get document() {
	    return $document;
	},
	set document(doc) {
	    $document = doc;
	},
        get history() {
            return $history;
        },
        get location() {
            return $location;
        },
        set location(uri) {
            uri = ENVJS.uri(uri);
            if ($location.href == uri) {
                $location.reload();
            } else if ($location.href == 'about:blank') {
                $location.assign(uri);
            } else {
                $location.replace(uri);
            }
        },
        get navigator() {
            return $navigator;
        },
        get parent() {
            return $parent;
        },
        get self() {
            return scope;
        },
 	setInterval: function(fn, time) {
	    DUMP(fn);
	},
	setTimeout: function(fn, time) {
	    DUMP(fn);
	},
        get top() {
            return __top__(scope);
        },
	get window() {
	    return this;
	},
     });
};

new Window(this, this);
