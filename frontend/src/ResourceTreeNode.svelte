<style>
  button {
    border: 0;
    margin: 0;
    padding-left: 0.5em;
    padding-right: 0.5em;
  }

  ul {
    list-style: none;
    margin: 0;
    padding-left: 1.5em;
    white-space: nowrap;
  }

  ul li {
    padding-left: 1.25em;
    border-left: 1px solid var(--main-fg-color);
  }

  ul li:before {
    content: "";
    border-bottom: 1px solid var(--main-fg-color);
    width: 1em;
    height: 0.25em;
    display: block;
    position: relative;
    left: -1.25em;
    top: 0.7em;
  }

  ul li:last-child {
    border-left: none;
    margin-top: -0.75em;
  }

  ul li:last-child:before {
    border-left: 1px solid var(--main-fg-color);
    height: 1em;
  }

  div.morebutton {
    padding-left: 1.25em;
    margin: 2em 0;
  }

  div.morebutton button {
    padding-top: 0.5em;
    padding-bottom: 0.5em;
    padding-left: 1em;
    padding-right: 1em;
    background-color: var(--main-bg-color);
    color: var(--main-fg-color);
    border: 1px solid var(--main-fg-color);
    border-radius: 0;
    font-size: smaller;
    overflow: hidden;
    box-shadow: none;
  }

  div.morebutton button:hover,
  div.morebutton button:focus {
    outline: none;
    box-shadow: inset 1px 1px 0 var(--main-fg-color),
      inset -1px -1px 0 var(--main-fg-color);
  }

  div.morebutton button:active {
    box-shadow: inset 2px 2px 0 var(--main-fg-color),
      inset -2px -2px 0 var(--main-fg-color);
  }

  .selected {
    background-color: var(--selected-bg-color);
    background-clip: border-box;
    color: var(--main-bg-color);
  }

  .comment {
    /* align with the caption above */
    padding-left: 1ch;
    margin: 0;
    color: var(--comment-color);
  }

  .comment button {
    padding: 0;
    padding-right: 0.5ch;
  }

  .comment :global(.comment_icon) {
    margin: 0;
    background-color: var(--comment-color);
  }
</style>

<script>
  import Icon from "./Icon.svelte";
  import Hoverable from "./Hoverable.svelte";
  import LoadingText from "./LoadingText.svelte";

  import { selected } from "./stores.js";
  import { shortcuts } from "./keyboard";

  export let rootResource,
    resourceNodeDataMap,
    selectNextSibling = () => {},
    selectPreviousSibling = () => {},
    collapsed = true,
    childrenCollapsed = true;
  let firstChild,
    childrenPromise,
    commentsPromise,
    self_id = rootResource.get_id(),
    kiddoChunksize = 512;

  $: {
    if (resourceNodeDataMap[self_id] === undefined) {
      resourceNodeDataMap[self_id] = {};
    }
    if (resourceNodeDataMap[self_id].collapsed === undefined) {
      resourceNodeDataMap[self_id].collapsed = collapsed;
    }
    if (resourceNodeDataMap[self_id].childrenPromise === undefined) {
      resourceNodeDataMap[self_id].childrenPromise =
        rootResource.get_children();
    }
    if (resourceNodeDataMap[self_id].commentsPromise === undefined) {
      resourceNodeDataMap[self_id].commentsPromise =
        rootResource.get_comments();
    }
    childrenPromise = resourceNodeDataMap[self_id].childrenPromise;
    commentsPromise = resourceNodeDataMap[self_id].commentsPromise;
    collapsed = resourceNodeDataMap[self_id].collapsed;
  }

  function updateRootModel() {
    rootResource.update();
    rootResource = rootResource;
  }
  $: updateRootModel(childrenPromise);

  $: childrenPromise?.then((children) => {
    if (children?.length > 0) {
      firstChild = children[0];
    }
  });

  $: if ($selected === self_id) {
    shortcuts["h"] = () => {
      resourceNodeDataMap[self_id].collapsed = true;
    };
    shortcuts["l"] = () => {
      resourceNodeDataMap[self_id].collapsed = false;
    };
    shortcuts["j"] = () => {
      if (!collapsed && firstChild) {
        $selected = firstChild?.resource_id;
      } else {
        selectNextSibling();
      }
    };
    shortcuts["k"] = selectPreviousSibling;

    shortcuts["arrowleft"] = shortcuts["h"];
    shortcuts["arrowdown"] = shortcuts["j"];
    shortcuts["arrowup"] = shortcuts["k"];
    shortcuts["arrowright"] = shortcuts["l"];
  }

  async function onClick(e) {
    // https://stackoverflow.com/a/53939059
    if (e.detail > 1) {
      return;
    }
    if ($selected === self_id) {
      $selected = undefined;
    } else {
      $selected = self_id;
    }
  }

  function onDoubleClick(e) {
    resourceNodeDataMap[self_id].collapsed = !collapsed;
    // Expand children recursively on double click
    if (!collapsed) {
      childrenCollapsed = false;
    }
    $selected = self_id;
  }

  async function onDeleteClick(optional_range) {
    // Delete the selected comment.
    // As a side effect, the corresponding resource gets selected.
    $selected = self_id;
    await rootResource.delete_comment(optional_range);
    resourceNodeDataMap[$selected].commentsPromise =
      rootResource.get_comments();
  }
</script>

{#await childrenPromise then children}
  {#if children?.length > 0}
    <button
      on:click="{() => {
        resourceNodeDataMap[self_id].collapsed = !collapsed;
      }}"
    >
      {#if collapsed}
        [+{children.length}]
      {:else}
        [-]
      {/if}
      <!-- Ugly next line is required to prevent Svelte from adding space after the button -->
    </button>{/if}{/await}<button
  on:click="{onClick}"
  on:dblclick="{onDoubleClick}"
  class:selected="{$selected === self_id}"
  id="{self_id}"
>
  {rootResource.get_caption()}
</button>
{#await commentsPromise then comments}
  {#each comments as comment}
    <div class="comment">
      <Hoverable let:hovering>
        <button
          title="Delete this comment"
          on:click="{onDeleteClick(comment[0])}"
        >
          <Icon
            class="comment_icon"
            url="{hovering ? '/icons/trash_can.svg' : '/icons/comment.svg'}"
          />
        </button></Hoverable
      >{comment[1]}
    </div>
  {/each}
{/await}

{#await childrenPromise}
  <LoadingText />
{:then children}
  {#if !collapsed && children.length > 0}
    <ul>
      {#each children.slice(0, kiddoChunksize) as child, i}
        <li>
          <div>
            <svelte:self
              rootResource="{child}"
              collapsed="{childrenCollapsed}"
              childrenCollapsed="{childrenCollapsed}"
              selectNextSibling="{i ===
              Math.min(kiddoChunksize, children.length) - 1
                ? selectNextSibling
                : () => {
                    $selected = children[i + 1]?.resource_id;
                  }}"
              selectPreviousSibling="{i === 0
                ? () => {
                    $selected = self_id;
                  }
                : () => {
                    $selected = children[i - 1]?.resource_id;
                  }}"
              bind:resourceNodeDataMap="{resourceNodeDataMap}"
            />
          </div>
        </li>
      {/each}
      {#if children.length > kiddoChunksize}
        <div class="morebutton">
          <button on:click="{() => (kiddoChunksize += 512)}">
            Show 512 more children...
          </button>
        </div>
      {/if}
    </ul>
  {/if}
{/await}
