@extends('layouts/default')

{{-- Page title --}}
@section('title')

  {{ trans('admin/suppliers/table.view') }} -
  {{ $supplier->name }}

  @parent
@stop

@section('header_right')
    <i class="fa-regular fa-2x fa-square-caret-right pull-right" id="expand-info-panel-button" data-tooltip="true" title="{{ trans('button.show_hide_info') }}"></i>
@endsection

{{-- Page content --}}
@section('content')
    <x-container columns="2">
        <x-page-column class="col-md-9 main-panel">
            <x-tabs>
                <x-slot:tabnav>
                    @can('view', \App\Models\Asset::class)
                        <x-tabs.nav-item
                            name="assets"
                            class="active"
                            icon="fas fa-barcode fa-fw"
                            label="{{ trans('general.assets') }}"
                            count="{{ $supplier->assets()->AssetsForShow()->count() }}"
                        />
                    @endcan

                    @can('view', \App\Models\License::class)
                        <x-tabs.nav-item
                                name="licenses"
                                icon="far fa-save"
                                label="{{ trans('general.licenses') }}"
                                count="{{ $supplier->licenses->count() }}"
                                tooltip="{{ trans('general.licenses') }}"
                        />
                    @endcan


                    @can('view', \App\Models\Accessory::class)
                        <x-tabs.nav-item
                                name="accessories"
                                icon="far fa-keyboard fa-fw"
                                label="{{ trans('general.accessories') }}"
                                count="{{ $supplier->accessories()->count() }}"
                        />
                    @endcan


                    @can('view', \App\Models\Consumable::class)
                        <x-tabs.nav-item
                                name="consumables"
                                icon="fas fa-tint fa-fw"
                                label="{{ trans('general.consumables') }}"
                                count="{{ $supplier->consumables()->count() }}"
                        />
                    @endcan

                    @can('view', \App\Models\Component::class)
                        <x-tabs.nav-item
                                name="components"
                                icon="fas fa-hdd fa-fw"
                                label="{{ trans('general.components') }}"
                                count="{{ $supplier->components->count() }}"
                        />
                    @endcan

                    @can('view', \App\Models\AssetMaintenance::class)
                        <x-tabs.nav-item
                                name="maintenances"
                                icon="fa-solid fa-screwdriver-wrench"
                                label="{{ trans('general.maintenances') }}"
                                count="{{ $supplier->maintenances->count() }}"
                        />
                    @endcan

                <x-tabs.nav-item
                    name="files"
                    icon="fa-solid fa-file-contract fa-fw"
                    label="{{ trans('general.files') }}"
                    count="{{ $supplier->uploads()->count() }}"
                />

                @can('update', $supplier)
                    <x-tabs.nav-item-upload />
                @endcan

                </x-slot:tabnav>



                <x-slot:tabpanes>

                    <!-- start assets tab pane -->
                    @can('view', \App\Models\Asset::class)
                        <x-tabs.pane name="assets" class="in active">
                            <x-slot:header>
                                {{ trans('general.assets') }}
                            </x-slot:header>

                            <x-slot:bulkactions>
                                <x-table.bulk-assets />
                            </x-slot:bulkactions>

                            <x-slot:content>
                                <x-table
                                        show_column_search="true"
                                        show_advanced_search="true"
                                        buttons="assetButtons"
                                        api_url="{{ route('api.assets.index', ['supplier_id' => $supplier->id, 'itemtype' => 'assets']) }}"
                                        :presenter="\App\Presenters\AssetPresenter::dataTableLayout()"
                                        export_filename="export-{{ str_slug($supplier->name) }}-assets-{{ date('Y-m-d') }}"
                                />
                            </x-slot:content>

                        </x-tabs.pane>
                    @endcan
                    <!-- end assets tab pane -->

                    <!-- start licenses tab pane -->
                    @can('view', \App\Models\License::class)
                        <x-tabs.pane name="licenses">
                            <x-slot:header>
                                {{ trans('general.licenses') }}
                            </x-slot:header>

                            <x-slot:content>
                                <x-table
                                        show_advanced_search="true"
                                        buttons="licenseButtons"
                                        api_url="{{ route('api.licenses.index', ['supplier_id' => $supplier->id]) }}"
                                        :presenter="\App\Presenters\LicensePresenter::dataTableLayout()"
                                        export_filename="export-{{ str_slug($supplier->name) }}-licenses-{{ date('Y-m-d') }}"
                                />
                            </x-slot:content>

                        </x-tabs.pane>
                    @endcan
                    <!-- end licenses tab pane -->

                    <!-- start accessories tab pane -->
                    @can('view', \App\Models\Accessory::class)
                        <x-tabs.pane name="accessories">
                            <x-slot:header>
                                {{ trans('general.accessories') }}
                            </x-slot:header>

                            <x-slot:content>
                                <x-table
                                        show_column_search="true"
                                        buttons="accessoryButtons"
                                        api_url="{{ route('api.accessories.index', ['supplier_id' => $supplier->id]) }}"
                                        :presenter="\App\Presenters\AccessoryPresenter::dataTableLayout()"
                                        export_filename="export-{{ str_slug($supplier->name) }}-accessories-{{ date('Y-m-d') }}"
                                />
                            </x-slot:content>

                        </x-tabs.pane>
                    @endcan
                    <!-- end accessories tab pane -->


                    <!-- start components tab pane -->
                    @can('view', \App\Models\Component::class)
                        <x-tabs.pane name="components">
                            <x-slot:header>
                                {{ trans('general.components') }}
                            </x-slot:header>

                            <x-slot:content>
                                <x-table
                                        show_advanced_search="true"
                                        buttons="componentButtons"
                                        api_url="{{ route('api.components.index', ['supplier_id' => $supplier->id]) }}"
                                        :presenter="\App\Presenters\ComponentPresenter::dataTableLayout()"
                                        export_filename="export-{{ str_slug($supplier->name) }}-components-{{ date('Y-m-d') }}"
                                />
                            </x-slot:content>
                        </x-tabs.pane>
                    @endcan
                    <!-- end components tab pane -->

                    <!-- start consumables tab pane -->
                    @can('view', \App\Models\Consumable::class)
                        <x-tabs.pane name="consumables">
                            <x-slot:header>
                                {{ trans('general.consumables') }}
                            </x-slot:header>

                            <x-slot:content>
                                <x-table
                                        show_advanced_search="true"
                                        buttons="consumableButtons"
                                        api_url="{{ route('api.consumables.index', ['supplier_id' => $supplier->id]) }}"
                                        :presenter="\App\Presenters\ConsumablePresenter::dataTableLayout()"
                                        export_filename="export-{{ str_slug($supplier->name) }}-consumables-{{ date('Y-m-d') }}"
                                />
                            </x-slot:content>
                        </x-tabs.pane>
                    @endcan
                    <!-- end consumables tab pane -->


                    <!-- start consumables tab pane -->
                    @can('view', \App\Models\Asset::class)
                        <x-tabs.pane name="maintenances">
                            <x-slot:header>
                                {{ trans('admin/maintenances/general.maintenances') }}
                            </x-slot:header>

                            <x-slot:content>
                                <x-table
                                        buttons="maintenanceButtons"
                                        api_url="{{ route('api.maintenances.index', ['supplier_id' => $supplier->id]) }}"
                                        :presenter="\App\Presenters\MaintenancesPresenter::dataTableLayout()"
                                        export_filename="export-{{ str_slug($supplier->name) }}-maintenances-{{ date('Y-m-d') }}"
                                />
                            </x-slot:content>
                        </x-tabs.pane>
                    @endcan
                    <!-- end consumables tab pane -->

                    <!-- start files tab pane -->
                    <x-tabs.pane name="files">
                        <x-slot:header>
                            {{ trans('general.files') }}
                        </x-slot:header>
                        <x-slot:content>
                            <x-filestable object_type="suppliers" :object="$supplier" />
                        </x-slot:content>
                    </x-tabs.pane>
                    <!-- end files tab pane -->

                </x-slot:tabpanes>

            </x-tabs>
        </x-page-column>
        <x-page-column class="col-md-3">

            <x-box>
                <x-box.info-panel :infoPanelObj="$supplier" img_path="{{ app('suppliers_upload_url') }}">

                    <x-slot:before_list>

                        @can('update', \App\Models\Supplier::class)
                            <a href="{{ ($supplier->deleted_at=='') ? route('suppliers.edit', $supplier->id) : '#' }}" class="btn btn-block btn-sm btn-warning btn-social hidden-print{{ ($supplier->deleted_at!='') ? ' disabled' : '' }}">
                                <x-icon type="edit" />
                                {{ trans('general.update') }}
                            </a>
                        @endcan

                        @can('delete', \App\Models\Supplier::class)

                            @if ($supplier->assets()->count() > 0)
                                <button class="btn btn-block btn-sm btn-danger btn-social hidden-print disabled" data-tooltip="true"  data-placement="top" data-title="{{ trans('general.cannot_be_deleted') }}">
                                    <x-icon type="delete" />
                                    {{ trans('general.delete') }}
                                </button>
                            @else
                                <button class="btn btn-block btn-sm btn-danger btn-social delete-asset" data-toggle="modal" title="{{ trans('general.delete_what', ['item'=> trans('general.supplier')]) }}" data-content="{{ trans('general.sure_to_delete_var', ['item' => $supplier->name]) }}" data-target="#dataConfirmModal" data-tooltip="true" data-icon="fa fa-trash" data-placement="top" data-title="{{ trans('general.delete_what', ['item'=> trans('general.supplier')]) }}" onClick="return false;">
                                    <x-icon type="delete" />
                                    {{ trans('general.delete') }}
                                </button>
                            @endif
                        @endcan

                    </x-slot:before_list>

                </x-box.info-panel>
            </x-box>
        </x-page-column>

    </x-container>


  @can('update', \App\Models\Supplier::class)
      @include ('modals.upload-file', ['item_type' => 'supplier', 'item_id' => $supplier->id])
  @endcan
@stop

@section('moar_scripts')
  @include ('partials.bootstrap-table', [
      'exportFile' => 'locations-export',
      'search' => true
   ])

@stop
