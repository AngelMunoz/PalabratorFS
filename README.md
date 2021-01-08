# PalabratorFs

Just a little sample using Saturn, Turbolinks and htmx

# Run
> ***NOTE***:this requires a mongodb server running

```
git clone
dotnet restore
dotnet watch run --no-restore
```

### Highlights
While the login is all about htmx/turbolinks, the Products page is a blend between js/ssr possible approaches
check `Views\Pages\Products\Products.html` and `Handlers.fs:481 (aprox.)` for more information.

This approach makes heavy use of WebComponents (with LitElement since it's the most friendly and the one that works just with esmodules in the browser (i.e no need for extra toolchain setup)).

Both `spc-products-list` and `spc-product-list-item` are webcomponents and must be defined somewhere in the JS files, they can be added on a general script file (i.e. a script that works just to import components) or import the specified script for the specified page
```html
<article>
    <h1>Sending static HTML</h1>
    <h2>Making it dynamic with web components on the front</h2>

    <!-- Send everything in JSON format and let the component take care of everything from the start -->
    <spc-products-list page="{{ page }}" limit="{{ limit }}" paginated='{{ serialized }}'></spc-products-list>

    <!-- Send the "wrapper" plus the content server side rendered at the beginning -->
    <spc-products-list page="{{ page }}" limit="{{ limit }}" paginated='{{ with_count_only }}' has-ssr-content>
        {{ for product in items.list }}
            <!-- Render the web components -->
            <spc-product-list-item product='{{ product }}'></spc-product-list-item>
        {{ end }}
    </spc-products-list>
</article>
```


For the JS Web Component I'll add what I believe to be the relevant parts and omit the rest, for more information check `wwwroot\WebComponents\Products.js`
```js
import {
    LitElement,
    html,
    css
} from "https://unpkg.com/lit-element@2.4.0/lit-element.js?module";
import { get } from "../utils.js";


class ProductList extends LitElement {
    static get properties() {
        return { 
            paginated: { type: Object },
            // NOTE: reflect: true is not necessary
            page: {type: Number, reflect: true },
            // I use it here just to update the attributes on the browser to see when the component updates the values
            limit: {type: Number, reflect: true },
            hasSsrContent: {type: Boolean, reflect: true, attribute: 'has-ssr-content'},
            // NOTE: attribute false means that these are internal properties and their values
            // are used to update the view in one way or another, so they must be tracked by LitElement
            detailedProduct: { type: Object, attribute: false },
            hasRequested: {type: Number, attribute: false }

        };
    }
    // previous/next work in the same way just backwards/forwards I'll omit _prev for those reasons
    async _next(e) {

        try {
            const result = await get(`/api/products?page=${(this.page || 1) + 1}&limit=${this.limit || 5}`)
            // we just requested json data
            // remove any server side rendered stuff to show the new data right away
            if (this.hasSsrContent && this.defaultSlot) {
                // NOTE: if the default slot is not removed,
                // it shows stale data and possibly hide the new data
                // since slots have preference over the internal content of the element
                this.defaultSlot.remove();
                this.hasSsrContent = false;
            }
            this.paginated = { ...result };
            this.page += 1;
        } catch (error) {
            console.warn({ error });
        }
    }

    render() {
        // Leverage the browser's event bubbling to catch events up and prevent callback drills
        // @selected-product is dispatched from ProductListItem (product-list-item)
        // @unselected-product is dispatched from ProductItemDetail (product-item-detail)
        return html`
        <article
            @selected-product="${(e) => (this.detailedProduct = e.detail)}"
            @unselect-product="${(e) => (this.detailedProduct = null)}">
            <section class="product-list">
            ${this.paginated.list.length > 0 ? 
                html`
                    ${this.paginated.list.map(this.getItem)}`
                    : null
                }
            <slot></slot>
            </section>
            ${this.detailedProduct ? this.detailedTemplate(this.detailedProduct) : null}
        </article>
        <aside class="pagination">
            <p>Showing ${this.showing} of ${this.paginated.count} products</p>
            <button .disabled="${this.isPrevDisabled}" @click="${this._previous}">Prev</button>
            <button .disabled="${this.isNextDisabled}" @click="${this._next}">Next</button>
        </aside>
        `;
    }

}
```
while turbolinks/htmx is a really nice way to work stuff, there may still a couple of things you need to take care about, like dynamic parts of your web app (e.g. navbar, sidebars, close buttons, etc.) which requires you to use JS anyways (check `wwwroot\index.js` for more information.) I feel a little bit un-ergonomic handling everything from the server, specially things that can be highly dynamic.

the second approach that I'm linking is to create a bunch of web components for things that have to be dynamic and render almost all of it from the server, you just need to prepare your web component to be ready and be aware to know what to do once dynamic stuff on the client is required, like in the example above which is fetching json to get a new page

Depending on how your views are defined and which browsers you need to support, you can get away most of the time with the second approach you may still need some polyfills though






### Extras

Products collection

```json
{
	"_id" : ObjectId("5fea2dd19ddb6b3624258f2c"),
	"name" : "Web Cam2",
	"price" : 20.57
},
{
	"_id" : ObjectId("5fea2dd19ddb6b3624258f2b"),
	"name" : "Speakers2",
	"price" : 45.3
},
{
	"_id" : ObjectId("5fea2dd19ddb6b3624258f2a"),
	"name" : "Tv2",
	"price" : 1200.2
},
{
	"_id" : ObjectId("5fea2dd19ddb6b3624258f29"),
	"name" : "Coffee Mug2",
	"price" : 5.36
},
{
	"_id" : ObjectId("5fea2dd19ddb6b3624258f28"),
	"name" : "Mouse2",
	"price" : 60.28
},
{
	"_id" : ObjectId("5fea2dd19ddb6b3624258f27"),
	"name" : "Keyboard2",
	"price" : 100
},
{
	"_id" : ObjectId("5fea2dd19ddb6b3624258f26"),
	"name" : "Paper2",
	"price" : 1.2
},
{
	"_id" : ObjectId("5fea2dd19ddb6b3624258f25"),
	"name" : "Beef2",
	"price" : 10.2
},
{
	"_id" : ObjectId("5fea2dd19ddb6b3624258f24"),
	"name" : "Shoes2",
	"price" : 20.57
},
{
	"_id" : ObjectId("5fea2dd19ddb6b3624258f23"),
	"name" : "Soap2",
	"price" : 2.2
},
{
	"_id" : ObjectId("5fea2db99ddb6b3624258f22"),
	"name" : "Web Cam",
	"price" : 20.57
},
{
	"_id" : ObjectId("5fea2db99ddb6b3624258f21"),
	"name" : "Speakers",
	"price" : 45.3
},
{
	"_id" : ObjectId("5fea2db99ddb6b3624258f20"),
	"name" : "Tv",
	"price" : 1200.2
},
{
	"_id" : ObjectId("5fea2db99ddb6b3624258f1f"),
	"name" : "Coffee Mug",
	"price" : 5.36
},
{
	"_id" : ObjectId("5fea2db99ddb6b3624258f1e"),
	"name" : "Mouse",
	"price" : 60.28
},
{
	"_id" : ObjectId("5fea2db99ddb6b3624258f1d"),
	"name" : "Keyboard",
	"price" : 100
},
{
	"_id" : ObjectId("5fea2db99ddb6b3624258f1c"),
	"name" : "Paper",
	"price" : 1.2
},
{
	"_id" : ObjectId("5fea2db99ddb6b3624258f1b"),
	"name" : "Beef",
	"price" : 10.2
},
{
	"_id" : ObjectId("5fea2db99ddb6b3624258f1a"),
	"name" : "Shoes",
	"price" : 20.57
},
{
	"_id" : ObjectId("5fea2db99ddb6b3624258f19"),
	"name" : "Soap",
	"price" : 2.2
}
```