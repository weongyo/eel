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

function __setArray__( target, array ) {
    target.length = 0;
    Array.prototype.push.apply(target, array);
}

/*----------------------------------------------------------------------*/

var ENVJS = {};

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
	if(!oldChild)
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

function __addEventListener__(target, type, fn, phase){
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
EventTarget.prototype.addEventListener = function(type, fn, phase){
    __addEventListener__(this, type, fn, phase);
};
EventTarget.prototype.removeEventListener = function(type, fn){
    DUMP(this);
};
EventTarget.prototype.dispatchEvent = function(event, bubbles){
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

/*----------------------------------------------------------------------*/

Attr = function(ownerDocument) {
    Node.apply(this, arguments);
    this.ownerElement = null;
};
Attr.prototype = new Node();
__extend__(Attr.prototype, {
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
    createDocumentFragment: function() {
        var node = new DocumentFragment(this);
        return (node);
    },
    get documentElement() {
	var i, length = this.childNodes ? this.childNodes.length : 0;

	for (i = 0; i < length; i++) {
	    if (this.childNodes[i].nodeType === Node.ELEMENT_NODE)
		return this.childNodes[i];
	}
	return null;
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
                if (target > -1 && target < $history.length){
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
    get style(){
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

HTMLParagraphElement = function(ownerDocument) {
    HTMLElement.apply(this, arguments);
};
HTMLParagraphElement.prototype = new HTMLElement();

/*----------------------------------------------------------------------*/

HTMLDocument = function(implementation, ownerWindow, referrer) {
    Document.apply(this, arguments);
    this.referrer = referrer || '';
    this.baseURI = "about:blank";
    this.ownerWindow = ownerWindow;
};
HTMLDocument.prototype = new Document();
__extend__(HTMLDocument.prototype, {
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
        case "P":
            node = new HTMLParagraphElement(this);
	    break;
	default:
	    DUMP(tagName);
	}
	node.nodeName  = tagName;
	return (node);
    },
    get documentElement() {
	var html = Document.prototype.__lookupGetter__('documentElement').apply(this,[]);
	if( html === null){
	    html = this.createElement('html');
	    this.appendChild(html);
	    html.appendChild(this.createElement('head'));
	    html.appendChild(this.createElement('body'));
	}
	return (html);
    },
    get location() {
        if (this.ownerWindow) {
            return this.ownerWindow.location;
        } else {
            return this.baseURI;
        }
    },
    set location(url) {
        this.baseURI = url;
        if (this.ownerWindow) {
            this.ownerWindow.location = url;
        }
    },
    open : function() {
        if (!this._writebuffer)
            this._writebuffer = [];
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

Location = function(url, doc, history) {
    var $url = url;
    var $document = doc ? doc : null;
    var $history = history ? history : null;
    var parts = ENVJS.urlsplit($url);

    return {
        get href() {
            return $url;
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
        get mimeTypes() {
	    DUMP(this);
        },
        get platform() {
	    DUMP(this);
        },
        get plugins() {
	    DUMP(this);
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

Window = function(scope, parent, opener) {
    scope.__defineGetter__('window', function () {
	return scope;
    });
    var $htmlImplementation = new DOMImplementation();
    var $document = new HTMLDocument($htmlImplementation, scope);
    var $history = new History();
    var $location = new Location('about:blank', $document, $history);
    var $navigator = new Navigator();
    __extend__(scope, EventTarget.prototype);
    return __extend__(scope, {
	get document() {
	    return $document;
	},
	set document(doc) {
	    $document = doc;
	},
        get location() {
            return $location;
        },
        set location(uri) {
            uri = Envjs.uri(uri);
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
	get window() {
	    return this;
	},
     });
};

new Window(this, this);
